#![allow(dead_code)]

use std::num::NonZeroI8;

use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_zk_sdk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::proof_data::PubkeyValidityProofData,
};
use spl_token_2022_interface::{
    extension::{
        confidential_transfer::{
            self, ConfidentialTransferAccount, DecryptableBalance, PENDING_BALANCE_LO_BIT_LENGTH,
        },
        BaseStateWithExtensions, ExtensionType,
    },
    id,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::{
    transfer_with_fee::{transfer_with_fee_split_proof_data, TransferWithFeeProofData},
    withdraw::{withdraw_proof_data, WithdrawProofData},
};

use super::{get_token_account_data, read_token_account_state, send};

pub struct ConfidentialAccount {
    pub address: Pubkey,
    pub owner: Keypair,
    pub elgamal: ElGamalKeypair,
    pub aes: AeKey,
}

/// Creates an auxiliary token account with room for the confidential-transfer
/// extensions, thaws it (post-KYC), and configures it for confidential
/// transfers with an owner-signed `ConfigureAccount` instruction. This is
/// deliberately separate from account creation (which anyone can pay for):
/// only the account owner can authorize `ConfigureAccount`, since it commits
/// the owner's ElGamal public key on-chain.
pub fn configure_confidential_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    mint_extensions: &[ExtensionType],
    owner: Keypair,
    freeze_authority: &Keypair,
) -> ConfidentialAccount {
    let account = super::create_auxiliary_token_account_with_extra_space(
        svm,
        payer,
        mint,
        &owner.pubkey(),
        mint_extensions,
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    );

    super::thaw(svm, payer, &account.pubkey(), mint, freeze_authority);

    let seed = account.pubkey().to_bytes();
    let elgamal = ElGamalKeypair::new_from_signer(&owner, &seed).unwrap();
    let aes = AeKey::new_from_signer(&owner, &seed).unwrap();

    let proof_data = PubkeyValidityProofData::new(&elgamal).unwrap();
    let proof_location = ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof_data);
    let decryptable_zero_balance: DecryptableBalance = aes.encrypt(0).into();

    let instructions = confidential_transfer::instruction::configure_account(
        &id(),
        &account.pubkey(),
        mint,
        &decryptable_zero_balance,
        65536,
        &owner.pubkey(),
        &[],
        proof_location,
    )
    .unwrap();

    send(svm, payer, &[payer, &owner], &instructions).unwrap();

    ConfidentialAccount {
        address: account.pubkey(),
        owner,
        elgamal,
        aes,
    }
}

/// The confidential-transfer authority approves an account for confidential
/// transfers (required because the reissued mint sets
/// `auto_approve_new_accounts: false`).
pub fn approve_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    confidential_authority: &Keypair,
) {
    let instruction = confidential_transfer::instruction::approve_account(
        &id(),
        account,
        mint,
        &confidential_authority.pubkey(),
        &[],
    )
    .unwrap();
    send(svm, payer, &[payer, confidential_authority], &[instruction]).unwrap();
}

/// Moves tokens from the account's public `amount` into its confidential
/// `pending_balance`. No zero-knowledge proof is required: the amount is
/// still plaintext and fully visible on-chain up to this point.
pub fn deposit(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    owner: &Keypair,
    amount: u64,
    decimals: u8,
) {
    let instruction = confidential_transfer::instruction::deposit(
        &id(),
        account,
        mint,
        amount,
        decimals,
        &owner.pubkey(),
        &[],
    )
    .unwrap();
    send(svm, payer, &[payer, owner], &[instruction]).unwrap();
}

/// Applies the account's pending balance into its available balance. Requires
/// the owner's own ElGamal secret key and AES key to decrypt the current
/// pending/available ciphertexts and re-encrypt the combined total -- a
/// permanent delegate holds neither and cannot perform this step.
pub fn apply_pending_balance(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    owner: &Keypair,
    elgamal: &ElGamalKeypair,
    aes: &AeKey,
) {
    let data = get_token_account_data(svm, account);
    let state = read_token_account_state(&data);
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();

    let pending_lo: ElGamalCiphertext = ext.pending_balance_lo.try_into().unwrap();
    let pending_hi: ElGamalCiphertext = ext.pending_balance_hi.try_into().unwrap();
    let decrypted_lo = elgamal.secret().decrypt_u32(&pending_lo).unwrap();
    let decrypted_hi = elgamal.secret().decrypt_u32(&pending_hi).unwrap();
    let pending_balance = decrypted_hi
        .checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .unwrap()
        .checked_add(decrypted_lo)
        .unwrap();

    let current_decryptable: AeCiphertext = ext.decryptable_available_balance.try_into().unwrap();
    let current_available = aes.decrypt(&current_decryptable).unwrap();
    let new_available = current_available.checked_add(pending_balance).unwrap();
    let new_decryptable_available_balance: DecryptableBalance = aes.encrypt(new_available).into();

    let expected_pending_balance_credit_counter: u64 = ext.pending_balance_credit_counter.into();

    let instruction = confidential_transfer::instruction::apply_pending_balance(
        &id(),
        account,
        expected_pending_balance_credit_counter,
        &new_decryptable_available_balance,
        &owner.pubkey(),
        &[],
    )
    .unwrap();
    send(svm, payer, &[payer, owner], &[instruction]).unwrap();
}

/// Confidential, fee-bearing transfer via `transfer_with_fee`. Generates the
/// full split proof set (equality, transfer-amount ciphertext validity,
/// percentage-with-cap fee sigma, fee ciphertext validity, range) and embeds
/// each proof as its own instruction in the same transaction
/// (`ProofLocation::InstructionOffset`), verified by the native
/// `zk_elgamal_proof_program` builtin.
#[allow(clippy::too_many_arguments)]
pub fn transfer_with_fee(
    svm: &mut LiteSVM,
    payer: &Keypair,
    source: &ConfidentialAccount,
    destination: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    auditor_elgamal_pubkey: Option<&ElGamalPubkey>,
    withdraw_withheld_authority_elgamal_pubkey: &ElGamalPubkey,
    fee_basis_points: u16,
    maximum_fee: u64,
) {
    let data = get_token_account_data(svm, &source.address);
    let state = read_token_account_state(&data);
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();

    let current_available_balance: ElGamalCiphertext = ext.available_balance.try_into().unwrap();
    let current_decryptable_available_balance: AeCiphertext =
        ext.decryptable_available_balance.try_into().unwrap();

    let destination_data = get_token_account_data(svm, destination);
    let destination_state = read_token_account_state(&destination_data);
    let destination_ext = destination_state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let destination_elgamal_pubkey: ElGamalPubkey =
        destination_ext.elgamal_pubkey.try_into().unwrap();

    let TransferWithFeeProofData {
        equality_proof_data,
        transfer_amount_ciphertext_validity_proof_data_with_ciphertext,
        percentage_with_cap_proof_data,
        fee_ciphertext_validity_proof_data,
        range_proof_data,
    } = transfer_with_fee_split_proof_data(
        &current_available_balance,
        &current_decryptable_available_balance,
        amount,
        &source.elgamal,
        &source.aes,
        &destination_elgamal_pubkey,
        auditor_elgamal_pubkey,
        withdraw_withheld_authority_elgamal_pubkey,
        fee_basis_points,
        maximum_fee,
    )
    .unwrap();

    let current_available = source
        .aes
        .decrypt(&current_decryptable_available_balance)
        .unwrap();
    let new_available = current_available.checked_sub(amount).unwrap();
    let new_source_decryptable_available_balance: DecryptableBalance =
        source.aes.encrypt(new_available).into();

    let equality_location =
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &equality_proof_data);
    let ciphertext_validity_location = ProofLocation::InstructionOffset(
        NonZeroI8::new(2).unwrap(),
        &transfer_amount_ciphertext_validity_proof_data_with_ciphertext.proof_data,
    );
    let fee_sigma_location = ProofLocation::InstructionOffset(
        NonZeroI8::new(3).unwrap(),
        &percentage_with_cap_proof_data,
    );
    let fee_ciphertext_validity_location = ProofLocation::InstructionOffset(
        NonZeroI8::new(4).unwrap(),
        &fee_ciphertext_validity_proof_data,
    );
    let range_location =
        ProofLocation::InstructionOffset(NonZeroI8::new(5).unwrap(), &range_proof_data);

    let instructions = confidential_transfer::instruction::transfer_with_fee(
        &id(),
        &source.address,
        mint,
        destination,
        &new_source_decryptable_available_balance,
        &transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        &transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        &source.owner.pubkey(),
        &[],
        equality_location,
        ciphertext_validity_location,
        fee_sigma_location,
        fee_ciphertext_validity_location,
        range_location,
    )
    .unwrap();

    send(svm, payer, &[payer, &source.owner], &instructions).unwrap();
}

/// Applies pending balance (if any is outstanding) and then withdraws
/// confidential tokens back to the account's public `amount`, per Task 6's
/// ordering requirement (apply before withdrawal).
pub fn withdraw(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &ConfidentialAccount,
    mint: &Pubkey,
    amount: u64,
    decimals: u8,
) {
    let data = get_token_account_data(svm, &account.address);
    let state = read_token_account_state(&data);
    let ext = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();

    let current_available_balance: ElGamalCiphertext = ext.available_balance.try_into().unwrap();
    let current_decryptable_available_balance: AeCiphertext =
        ext.decryptable_available_balance.try_into().unwrap();
    let current_available = account
        .aes
        .decrypt(&current_decryptable_available_balance)
        .unwrap();

    let WithdrawProofData {
        equality_proof_data,
        range_proof_data,
    } = withdraw_proof_data(
        &current_available_balance,
        current_available,
        amount,
        &account.elgamal,
    )
    .unwrap();

    let new_available = current_available.checked_sub(amount).unwrap();
    let new_decryptable_available_balance: DecryptableBalance =
        account.aes.encrypt(new_available).into();

    let equality_location =
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &equality_proof_data);
    let range_location =
        ProofLocation::InstructionOffset(NonZeroI8::new(2).unwrap(), &range_proof_data);

    let instructions = confidential_transfer::instruction::withdraw(
        &id(),
        &account.address,
        mint,
        amount,
        decimals,
        &new_decryptable_available_balance,
        &account.owner.pubkey(),
        &[],
        equality_location,
        range_location,
    )
    .unwrap();

    send(svm, payer, &[payer, &account.owner], &instructions).unwrap();
}
