use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use spl_token_2022_interface::{
    extension::{
        confidential_transfer, confidential_transfer_fee, default_account_state, metadata_pointer,
        transfer_fee::{self, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{self, TokenInstruction},
    state::{Account, AccountState, Mint},
};

pub const DECIMALS: u8 = 6;
pub const TRANSFER_FEE_BASIS_POINTS: u16 = 100;
pub const MAXIMUM_FEE: u64 = 5_000_000;

pub const BASE_MINT_EXTENSIONS: [ExtensionType; 4] = [
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
];

pub const CONFIDENTIAL_MINT_EXTENSIONS: [ExtensionType; 7] = [
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
    ExtensionType::PermanentDelegate,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintPlan {
    pub account_len: usize,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Debug)]
pub struct MintAuthorities {
    pub mint_authority: Pubkey,
    pub freeze_authority: Pubkey,
    pub fee_config_authority: Pubkey,
    pub withdraw_withheld_authority: Pubkey,
    pub metadata_authority: Pubkey,
    pub close_authority: Pubkey,
}

pub fn base_mint_plan(
    mint: &Pubkey,
    authorities: &MintAuthorities,
) -> Result<MintPlan, ProgramError> {
    let account_len = ExtensionType::try_calculate_account_len::<Mint>(&BASE_MINT_EXTENSIONS)?;
    let mut instructions = base_extension_initializers(mint, authorities)?;
    instructions.push(instruction::initialize_mint2(
        &spl_token_2022_interface::id(),
        mint,
        &authorities.mint_authority,
        Some(&authorities.freeze_authority),
        DECIMALS,
    )?);

    Ok(MintPlan {
        account_len,
        instructions,
    })
}

pub fn confidential_mint_plan(
    mint: &Pubkey,
    authorities: &MintAuthorities,
    permanent_delegate: &Pubkey,
    confidential_authority: &Pubkey,
    confidential_fee_authority: &Pubkey,
    withdraw_withheld_elgamal_pubkey: &spl_token_2022_interface::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey,
    auditor_elgamal_pubkey: Option<
        spl_token_2022_interface::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey,
    >,
) -> Result<MintPlan, ProgramError> {
    let account_len =
        ExtensionType::try_calculate_account_len::<Mint>(&CONFIDENTIAL_MINT_EXTENSIONS)?;
    let mut instructions = base_extension_initializers(mint, authorities)?;
    instructions.push(instruction::initialize_permanent_delegate(
        &spl_token_2022_interface::id(),
        mint,
        permanent_delegate,
    )?);
    instructions.push(confidential_transfer::instruction::initialize_mint(
        &spl_token_2022_interface::id(),
        mint,
        Some(*confidential_authority),
        false,
        auditor_elgamal_pubkey,
    )?);
    // A mint that combines TransferFeeConfig with confidential transfers needs the
    // confidential fee companion extension, otherwise fee-bearing ciphertext
    // transfers cannot account for withheld fees.
    instructions.push(
        confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config(
            &spl_token_2022_interface::id(),
            mint,
            Some(*confidential_fee_authority),
            withdraw_withheld_elgamal_pubkey,
        )?,
    );
    instructions.push(instruction::initialize_mint2(
        &spl_token_2022_interface::id(),
        mint,
        &authorities.mint_authority,
        Some(&authorities.freeze_authority),
        DECIMALS,
    )?);

    Ok(MintPlan {
        account_len,
        instructions,
    })
}

fn base_extension_initializers(
    mint: &Pubkey,
    authorities: &MintAuthorities,
) -> Result<Vec<Instruction>, ProgramError> {
    Ok(vec![
        transfer_fee::instruction::initialize_transfer_fee_config(
            &spl_token_2022_interface::id(),
            mint,
            Some(&authorities.fee_config_authority),
            Some(&authorities.withdraw_withheld_authority),
            TRANSFER_FEE_BASIS_POINTS,
            MAXIMUM_FEE,
        )?,
        metadata_pointer::instruction::initialize(
            &spl_token_2022_interface::id(),
            mint,
            Some(authorities.metadata_authority),
            Some(*mint),
        )?,
        default_account_state::instruction::initialize_default_account_state(
            &spl_token_2022_interface::id(),
            mint,
            &AccountState::Frozen,
        )?,
        instruction::initialize_mint_close_authority(
            &spl_token_2022_interface::id(),
            mint,
            Some(&authorities.close_authority),
        )?,
    ])
}

pub fn metadata_initialize_instruction(
    mint: &Pubkey,
    mint_authority: &Pubkey,
    update_authority: &Pubkey,
    name: impl Into<String>,
    symbol: impl Into<String>,
    uri: impl Into<String>,
) -> Instruction {
    spl_token_metadata_interface::instruction::initialize(
        &spl_token_2022_interface::id(),
        mint,
        update_authority,
        mint,
        mint_authority,
        name.into(),
        symbol.into(),
        uri.into(),
    )
}

pub fn transfer_with_current_epoch_fee(
    mint_data: &[u8],
    current_epoch: u64,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Result<(Instruction, u64), ProgramError> {
    let mint_state = read_mint(mint_data)?;
    let fee_config = mint_state.get_extension::<TransferFeeConfig>()?;
    let expected_fee = fee_config
        .calculate_epoch_fee(current_epoch, amount)
        .ok_or(ProgramError::InvalidArgument)?;
    let instruction = transfer_fee::instruction::transfer_checked_with_fee(
        &spl_token_2022_interface::id(),
        source,
        mint,
        destination,
        authority,
        &[],
        amount,
        mint_state.base.decimals,
        expected_fee,
    )?;

    Ok((instruction, expected_fee))
}

pub fn thaw_after_kyc(
    token_account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Pubkey,
) -> Result<Instruction, ProgramError> {
    instruction::thaw_account(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        freeze_authority,
        &[],
    )
}

pub fn read_mint(data: &[u8]) -> Result<StateWithExtensions<'_, Mint>, ProgramError> {
    StateWithExtensions::<Mint>::unpack(data)
}

pub fn read_token_account(data: &[u8]) -> Result<StateWithExtensions<'_, Account>, ProgramError> {
    StateWithExtensions::<Account>::unpack(data)
}

pub fn ends_with_initialize_mint(plan: &MintPlan) -> bool {
    plan.instructions
        .last()
        .and_then(|ix| TokenInstruction::unpack(&ix.data).ok())
        .is_some_and(|ix| matches!(ix, TokenInstruction::InitializeMint2 { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorities() -> MintAuthorities {
        MintAuthorities {
            mint_authority: Pubkey::new_unique(),
            freeze_authority: Pubkey::new_unique(),
            fee_config_authority: Pubkey::new_unique(),
            withdraw_withheld_authority: Pubkey::new_unique(),
            metadata_authority: Pubkey::new_unique(),
            close_authority: Pubkey::new_unique(),
        }
    }

    #[test]
    fn all_extension_initializers_precede_initialize_mint() {
        let mint = Pubkey::new_unique();
        let authorities = authorities();
        let base = base_mint_plan(&mint, &authorities).unwrap();
        let confidential = confidential_mint_plan(
            &mint,
            &authorities,
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &spl_token_2022_interface::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey::from(
                *spl_token_2022_interface::solana_zk_sdk::encryption::elgamal::ElGamalKeypair::new_rand().pubkey(),
            ),
            Some(spl_token_2022_interface::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey::from(
                *spl_token_2022_interface::solana_zk_sdk::encryption::elgamal::ElGamalKeypair::new_rand().pubkey(),
            )),
        )
        .unwrap();

        assert_eq!(base.instructions.len(), 5);
        assert_eq!(confidential.instructions.len(), 8);
        assert!(ends_with_initialize_mint(&base));
        assert!(ends_with_initialize_mint(&confidential));
        assert_eq!(
            base.account_len,
            ExtensionType::try_calculate_account_len::<Mint>(&BASE_MINT_EXTENSIONS).unwrap()
        );
        assert_eq!(
            confidential.account_len,
            ExtensionType::try_calculate_account_len::<Mint>(&CONFIDENTIAL_MINT_EXTENSIONS)
                .unwrap()
        );
    }
}
