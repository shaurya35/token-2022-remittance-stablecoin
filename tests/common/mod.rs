#![allow(dead_code)]

pub mod confidential;

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spl_token_2022_interface::{
    extension::{ExtensionType, StateWithExtensions},
    id,
    state::{Account, Mint},
};
use token_2022_remittance_stablecoin::MintPlan;

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::new_from_array(*keypair.secret_bytes())
}

/// Fresh LiteSVM instance. `LiteSVM::new()` loads the standard SPL builtins
/// (including a Token-2022 program build and, via `FeatureSet::all_enabled()`,
/// the native `zk_elgamal_proof_program` builtin required to verify
/// confidential-transfer proofs).
///
/// LiteSVM 0.10.0's *bundled* Token-2022 binary is compiled without the
/// `zk-ops` Cargo feature, so every confidential-transfer instruction that
/// actually moves value (`Deposit`, `Withdraw`, `Transfer`,
/// `TransferWithFee`, `ApplyPendingBalance`) unconditionally returns
/// `InvalidInstructionData` -- administrative instructions like
/// `ConfigureAccount`/`ApproveAccount` are unaffected since they aren't
/// feature-gated. We rebuilt `spl-token-2022` v10.0.0 locally with
/// `cargo build-sbf` (default features, which include `zk-ops`) and load
/// that binary over the same program id here so the confidential lifecycle
/// actually executes.
pub fn new_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(
        id(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/spl_token_2022_zkops.so"
        ),
    )
    .unwrap();
    svm
}

pub fn fund(svm: &mut LiteSVM, account: &Pubkey) {
    svm.airdrop(account, 100 * LAMPORTS_PER_SOL).unwrap();
}

pub fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    instructions: &[Instruction],
) -> Result<(), String> {
    let message =
        Message::new_with_blockhash(instructions, Some(&payer.pubkey()), &svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), signers)
        .map_err(|error| error.to_string())?;
    let result = svm.send_transaction(tx);
    svm.expire_blockhash();
    result.map(|_| ()).map_err(|error| format!("{error:?}"))
}

/// Creates and fully initializes a Token-2022 mint from a `MintPlan`
/// (`base_mint_plan` or `confidential_mint_plan` from the library). This is a
/// single atomic transaction: `create_account` sized via
/// `ExtensionType::try_calculate_account_len`, followed by every
/// extension-initializer instruction, followed by `InitializeMint2`.
pub fn create_mint_from_plan(svm: &mut LiteSVM, payer: &Keypair, mint: &Keypair, plan: &MintPlan) {
    let create_account = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        svm.minimum_balance_for_rent_exemption(plan.account_len),
        plan.account_len as u64,
        &id(),
    );

    let mut instructions = vec![create_account];
    instructions.extend(plan.instructions.clone());

    send(svm, payer, &[payer, mint], &instructions).unwrap();
}

/// Creates a plain (non-confidential) auxiliary token account sized to hold
/// whichever account-level extensions the mint requires (e.g.
/// `TransferFeeAmount` for a mint carrying `TransferFeeConfig`).
pub fn create_auxiliary_token_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
    mint_extensions: &[ExtensionType],
) -> Keypair {
    create_auxiliary_token_account_with_extra_space(svm, payer, mint, owner, mint_extensions, &[])
}

/// Creates an auxiliary token account with extra account-level extension
/// space beyond what the mint strictly requires at `InitializeAccount` time
/// (e.g. `ConfidentialTransferAccount` + `ConfidentialTransferFeeAmount`,
/// which are opt-in per account and configured later via
/// `ConfigureAccount`).
pub fn create_auxiliary_token_account_with_extra_space(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
    mint_extensions: &[ExtensionType],
    extra_extensions: &[ExtensionType],
) -> Keypair {
    let account = Keypair::new();
    let mut extensions = ExtensionType::get_required_init_account_extensions(mint_extensions);
    for extension in extra_extensions {
        if !extensions.contains(extension) {
            extensions.push(*extension);
        }
    }
    let account_len = ExtensionType::try_calculate_account_len::<Account>(&extensions).unwrap();

    let create_account = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &account.pubkey(),
        svm.minimum_balance_for_rent_exemption(account_len),
        account_len as u64,
        &id(),
    );
    let initialize = spl_token_2022_interface::instruction::initialize_account3(
        &id(),
        &account.pubkey(),
        mint,
        owner,
    )
    .unwrap();

    send(
        svm,
        payer,
        &[payer, &account],
        &[create_account, initialize],
    )
    .unwrap();
    account
}

pub fn mint_to(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Keypair,
    amount: u64,
) {
    let signers: Vec<&Keypair> = if payer.pubkey() == authority.pubkey() {
        vec![payer]
    } else {
        vec![payer, authority]
    };
    let instruction = spl_token_2022_interface::instruction::mint_to(
        &id(),
        mint,
        destination,
        &authority.pubkey(),
        &[],
        amount,
    )
    .unwrap();
    send(svm, payer, &signers, &[instruction]).unwrap();
}

pub fn thaw(
    svm: &mut LiteSVM,
    payer: &Keypair,
    account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Keypair,
) {
    let signers: Vec<&Keypair> = if payer.pubkey() == freeze_authority.pubkey() {
        vec![payer]
    } else {
        vec![payer, freeze_authority]
    };
    let instruction =
        token_2022_remittance_stablecoin::thaw_after_kyc(account, mint, &freeze_authority.pubkey())
            .unwrap();
    send(svm, payer, &signers, &[instruction]).unwrap();
}

pub fn get_mint_data(svm: &LiteSVM, mint: &Pubkey) -> Vec<u8> {
    svm.get_account(mint).unwrap().data
}

pub fn read_mint_state(data: &[u8]) -> StateWithExtensions<'_, Mint> {
    token_2022_remittance_stablecoin::read_mint(data).unwrap()
}

pub fn get_token_account_data(svm: &LiteSVM, account: &Pubkey) -> Vec<u8> {
    svm.get_account(account).unwrap().data
}

pub fn read_token_account_state(data: &[u8]) -> StateWithExtensions<'_, Account> {
    token_2022_remittance_stablecoin::read_token_account(data).unwrap()
}
