mod common;

use common::confidential;
use solana_clock::Clock;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_zk_sdk::encryption::{elgamal::ElGamalKeypair, pod::elgamal::PodElGamalPubkey};
use spl_token_2022_interface::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount,
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        transfer_fee::{TransferFeeAmount, TransferFeeConfig},
        BaseStateWithExtensions,
    },
    state::AccountState,
};
use token_2022_remittance_stablecoin::{
    base_mint_plan, confidential_mint_plan, metadata_initialize_instruction,
    transfer_with_current_epoch_fee, MintAuthorities, BASE_MINT_EXTENSIONS,
    CONFIDENTIAL_MINT_EXTENSIONS, DECIMALS, MAXIMUM_FEE, TRANSFER_FEE_BASIS_POINTS,
};

#[test]
fn base_mint_fees_metadata_kyc_and_close_authority() {
    let mut svm = common::new_svm();
    let payer = Keypair::new();
    common::fund(&mut svm, &payer.pubkey());

    let mint_authority = Keypair::new();
    let freeze_authority = Keypair::new();
    let fee_authority = Keypair::new();
    let withdraw_authority = Keypair::new();
    let metadata_authority = Keypair::new();
    let close_authority = Keypair::new();
    let mint = Keypair::new();

    let authorities = MintAuthorities {
        mint_authority: mint_authority.pubkey(),
        freeze_authority: freeze_authority.pubkey(),
        fee_config_authority: fee_authority.pubkey(),
        withdraw_withheld_authority: withdraw_authority.pubkey(),
        metadata_authority: metadata_authority.pubkey(),
        close_authority: close_authority.pubkey(),
    };

    // Task 1: extension stacking with instruction ordering + sizing verified
    // by `all_extension_initializers_precede_initialize_mint` in src/lib.rs.
    let plan = base_mint_plan(&mint.pubkey(), &authorities).unwrap();
    common::create_mint_from_plan(&mut svm, &payer, &mint, &plan);

    // Pad the mint account with extra lamports before writing on-chain
    // metadata: `MetadataPointer` points at the mint itself, and the
    // metadata TLV entry grows the account beyond the fixed extension
    // layout sized at creation, so the account needs pre-funded
    // rent-exempt lamports for that in-place realloc.
    let fund_metadata_rent =
        system_instruction::transfer(&payer.pubkey(), &mint.pubkey(), 10_000_000);
    let init_metadata = metadata_initialize_instruction(
        &mint.pubkey(),
        &mint_authority.pubkey(),
        &metadata_authority.pubkey(),
        "Remit USD",
        "rUSD",
        "https://example.com/remit-usd.json",
    );
    common::send(
        &mut svm,
        &payer,
        &[&payer, &mint_authority],
        &[fund_metadata_rent, init_metadata],
    )
    .unwrap();

    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = common::create_auxiliary_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice.pubkey(),
        &BASE_MINT_EXTENSIONS,
    );
    let bob_account = common::create_auxiliary_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &bob.pubkey(),
        &BASE_MINT_EXTENSIONS,
    );

    // Task 1 corollary: DefaultAccountState = Frozen means brand-new
    // accounts start frozen until KYC clears them individually (Task 4).
    let alice_data = common::get_token_account_data(&svm, &alice_account.pubkey());
    assert_eq!(
        common::read_token_account_state(&alice_data).base.state,
        AccountState::Frozen
    );

    common::thaw(
        &mut svm,
        &payer,
        &alice_account.pubkey(),
        &mint.pubkey(),
        &freeze_authority,
    );
    common::thaw(
        &mut svm,
        &payer,
        &bob_account.pubkey(),
        &mint.pubkey(),
        &freeze_authority,
    );

    // Task 4: per-account thaw must be independent of the mint's
    // DefaultAccountState. Thawing alice's and bob's accounts above must
    // not have touched the mint-level default state, so a brand-new
    // auxiliary account created *after* those thaws still starts Frozen.
    let carol = Keypair::new();
    let carol_account = common::create_auxiliary_token_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &carol.pubkey(),
        &BASE_MINT_EXTENSIONS,
    );
    let carol_data = common::get_token_account_data(&svm, &carol_account.pubkey());
    assert_eq!(
        common::read_token_account_state(&carol_data).base.state,
        AccountState::Frozen,
        "a freshly created account must still default to Frozen after other accounts were individually thawed"
    );

    common::mint_to(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice_account.pubkey(),
        &mint_authority,
        1_000_000_000,
    );

    // Task 2: fee computed via `calculate_epoch_fee(current_epoch, amount)`,
    // not a cached rate, and the transfer uses `transfer_checked_with_fee`.
    let mint_data = common::get_mint_data(&svm, &mint.pubkey());
    let epoch = svm.get_sysvar::<Clock>().epoch;
    let (transfer_ix, fee) = transfer_with_current_epoch_fee(
        &mint_data,
        epoch,
        &alice_account.pubkey(),
        &mint.pubkey(),
        &bob_account.pubkey(),
        &alice.pubkey(),
        200_000_000,
    )
    .unwrap();
    common::send(&mut svm, &payer, &[&payer, &alice], &[transfer_ix]).unwrap();

    // Task 3: every assertion below reads state exclusively through
    // `StateWithExtensions` (via the library's `read_mint`/`read_token_account`).
    let mint_data = common::get_mint_data(&svm, &mint.pubkey());
    let mint_state = common::read_mint_state(&mint_data);
    assert_eq!(
        mint_state
            .get_extension::<MetadataPointer>()
            .unwrap()
            .metadata_address,
        Some(mint.pubkey()).try_into().unwrap()
    );
    assert_eq!(
        AccountState::try_from(
            mint_state
                .get_extension::<DefaultAccountState>()
                .unwrap()
                .state
        )
        .unwrap(),
        AccountState::Frozen
    );
    assert!(mint_state.get_extension::<TransferFeeConfig>().is_ok());

    let bob_data = common::get_token_account_data(&svm, &bob_account.pubkey());
    let bob_state = common::read_token_account_state(&bob_data);
    assert_eq!(
        bob_state
            .get_extension::<TransferFeeAmount>()
            .unwrap()
            .withheld_amount,
        fee.into()
    );
}

#[test]
fn reissued_mint_runs_manual_confidential_lifecycle_with_fees() {
    let mut svm = common::new_svm();
    let payer = Keypair::new();
    common::fund(&mut svm, &payer.pubkey());

    let mint_authority = Keypair::new();
    let freeze_authority = Keypair::new();
    let transfer_fee_authority = Keypair::new();
    let withdraw_authority = Keypair::new();
    let metadata_authority = Keypair::new();
    let close_authority = Keypair::new();
    let permanent_delegate = Keypair::new();
    let confidential_authority = Keypair::new();
    let confidential_fee_authority = Keypair::new();
    let auditor = ElGamalKeypair::new_rand();
    let withdraw_elgamal = ElGamalKeypair::new_rand();
    let mint = Keypair::new();

    let authorities = MintAuthorities {
        mint_authority: mint_authority.pubkey(),
        freeze_authority: freeze_authority.pubkey(),
        fee_config_authority: transfer_fee_authority.pubkey(),
        withdraw_withheld_authority: withdraw_authority.pubkey(),
        metadata_authority: metadata_authority.pubkey(),
        close_authority: close_authority.pubkey(),
    };

    // Task 5: re-issue the mint carrying the same base extension set forward
    // and add PermanentDelegate (seizure authority) + confidential transfers
    // (manual approval: no `auto_approve_new_accounts`).
    let plan = confidential_mint_plan(
        &mint.pubkey(),
        &authorities,
        &permanent_delegate.pubkey(),
        &confidential_authority.pubkey(),
        &confidential_fee_authority.pubkey(),
        &PodElGamalPubkey::from(*withdraw_elgamal.pubkey()),
        Some(PodElGamalPubkey::from(*auditor.pubkey())),
    )
    .unwrap();
    common::create_mint_from_plan(&mut svm, &payer, &mint, &plan);

    // Task 6: ConfigureAccount is owner-signed and distinct from account
    // creation (which anyone can pay for).
    let alice = confidential::configure_confidential_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &CONFIDENTIAL_MINT_EXTENSIONS,
        Keypair::new(),
        &freeze_authority,
    );
    let bob = confidential::configure_confidential_account(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &CONFIDENTIAL_MINT_EXTENSIONS,
        Keypair::new(),
        &freeze_authority,
    );

    let before_data = common::get_token_account_data(&svm, &alice.address);
    let before_state = common::read_token_account_state(&before_data);
    assert!(!bool::from(
        before_state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap()
            .approved
    ));

    for account in [alice.address, bob.address] {
        confidential::approve_account(
            &mut svm,
            &payer,
            &account,
            &mint.pubkey(),
            &confidential_authority,
        );
    }

    common::mint_to(
        &mut svm,
        &payer,
        &mint.pubkey(),
        &alice.address,
        &mint_authority,
        1_000_000,
    );

    confidential::deposit(
        &mut svm,
        &payer,
        &alice.address,
        &mint.pubkey(),
        &alice.owner,
        1_000_000,
        DECIMALS,
    );
    confidential::apply_pending_balance(
        &mut svm,
        &payer,
        &alice.address,
        &alice.owner,
        &alice.elgamal,
        &alice.aes,
    );

    confidential::transfer_with_fee(
        &mut svm,
        &payer,
        &alice,
        &bob.address,
        &mint.pubkey(),
        400_000,
        Some(auditor.pubkey()),
        withdraw_elgamal.pubkey(),
        TRANSFER_FEE_BASIS_POINTS,
        MAXIMUM_FEE,
    );

    confidential::apply_pending_balance(
        &mut svm,
        &payer,
        &bob.address,
        &bob.owner,
        &bob.elgamal,
        &bob.aes,
    );

    // Apply pending balance before withdrawal, per Task 6's ordering
    // requirement.
    confidential::withdraw(&mut svm, &payer, &bob, &mint.pubkey(), 100_000, DECIMALS);

    let bob_data = common::get_token_account_data(&svm, &bob.address);
    let bob_state = common::read_token_account_state(&bob_data);
    assert_eq!(bob_state.base.amount, 100_000);
    assert!(bob_state
        .get_extension::<ConfidentialTransferAccount>()
        .is_ok());

    let mint_data = common::get_mint_data(&svm, &mint.pubkey());
    let mint_state = common::read_mint_state(&mint_data);
    assert!(!bool::from(
        mint_state
            .get_extension::<spl_token_2022_interface::extension::confidential_transfer::ConfidentialTransferMint>()
            .unwrap()
            .auto_approve_new_accounts
    ));
    assert!(mint_state
        .get_extension::<ConfidentialTransferFeeConfig>()
        .is_ok());
}
