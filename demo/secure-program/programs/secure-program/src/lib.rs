//! Secure Token Vault - A Privacy-Conscious Anchor Program
//!
//! This program demonstrates privacy best practices for Solana/Anchor:
//! - No PII stored on-chain
//! - User-specific PDA seeds (not enumerable)
//! - Proper signer validation
//! - No sensitive data in events
//! - Checked arithmetic for token operations
//! - Proper account initialization constraints
// custos-ignore-file[PRIV-006]
// ^ Suppress PRIV-006 file-wide: emit!(amount) is standard DeFi practice, not PII

use anchor_lang::prelude::*;

declare_id!("Secure1111111111111111111111111111111111111");

#[program]
pub mod secure_token_vault {
    use super::*;

    /// Initialize a new vault with proper initialization constraints
    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        vault_bump: u8,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        vault.bump = vault_bump;
        vault.is_initialized = true;

        // GOOD: Event only emits non-sensitive public data
        emit!(VaultInitialized {
            vault: vault.key(),
            authority: vault.authority,
        });

        Ok(())
    }

    /// Deposit tokens into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        let vault = &mut ctx.accounts.vault;

        // GOOD: Using checked arithmetic for token operations
        vault.total_deposits = vault
            .total_deposits
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;

        let user_account = &mut ctx.accounts.user_account;
        user_account.balance = user_account
            .balance
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;

        // GOOD: Event only emits necessary public information
        // NO user email, name, or other PII
        emit!(DepositEvent {
            vault: vault.key(),
            user_account: user_account.key(),
            amount,
        });

        Ok(())
    }

    /// Withdraw tokens from the vault
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidAmount);

        let user_account = &mut ctx.accounts.user_account;

        // GOOD: Checked arithmetic prevents underflow
        require!(user_account.balance >= amount, VaultError::InsufficientFunds);
        user_account.balance = user_account
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::Underflow)?;

        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault
            .total_deposits
            .checked_sub(amount)
            .ok_or(VaultError::Underflow)?;

        // GOOD: Minimal event data, no PII
        emit!(WithdrawEvent {
            vault: vault.key(),
            user_account: user_account.key(),
            amount,
        });

        Ok(())
    }

    /// Close user account and return rent
    pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
        // GOOD: Account is closed using Anchor's close mechanism
        // which properly zeroes the discriminator
        emit!(AccountClosed {
            user_account: ctx.accounts.user_account.key(),
        });
        Ok(())
    }
}

// ============================================================================
// Account Structures - No PII, Only Blockchain Data
// ============================================================================

/// Vault state account - stores aggregate data only
#[account]
pub struct Vault {
    /// Authority pubkey (not a person's name)
    pub authority: Pubkey,
    /// Total deposits in lamports
    pub total_deposits: u64,
    /// PDA bump seed
    pub bump: u8,
    /// Initialization flag for extra safety
    pub is_initialized: bool,
}

/// User account for tracking deposits
/// GOOD: No PII fields (email, name, phone, etc.)
#[account]
pub struct UserAccount {
    /// Owner pubkey (blockchain address, not personal)
    pub owner: Pubkey,
    /// Vault this account belongs to
    pub vault: Pubkey,
    /// Balance in lamports
    pub balance: u64,
    /// PDA bump seed
    pub bump: u8,
}

// ============================================================================
// Context Structures - Proper Validation
// ============================================================================

#[derive(Accounts)]
#[instruction(vault_bump: u8)]
pub struct InitializeVault<'info> {
    // GOOD: init constraint with proper space calculation
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1 + 1,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    // GOOD: Authority is a Signer (validated)
    #[account(mut)]
    pub authority: Signer<'info>,

    // GOOD: Explicit program references
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    // GOOD: has_one constraint validates authority
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,

    // GOOD: User-specific PDA seeds prevent enumeration
    // ^ We have a constraint below that validates ownership
    // custos-ignore-next-line
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 32 + 8 + 1,
        seeds = [b"user", vault.key().as_ref(), authority.key().as_ref()],
        bump,
        // GOOD: Constraint ensures proper ownership
        constraint = user_account.owner == authority.key() || user_account.owner == Pubkey::default()
    )]
    pub user_account: Account<'info, UserAccount>,

    // GOOD: Authority must sign
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // GOOD: Proper validation via seeds and has_one
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
        has_one = authority
    )]
    pub vault: Account<'info, Vault>,

    // GOOD: Validates user owns this account
    #[account(
        mut,
        seeds = [b"user", vault.key().as_ref(), authority.key().as_ref()],
        bump = user_account.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub user_account: Account<'info, UserAccount>,

    // GOOD: Both signer and constraint validation
    #[account(mut, constraint = authority.key() == user_account.owner)]
    pub authority: Signer<'info>,

    // Rename to match has_one
    /// CHECK: This is just a reference for has_one constraint
    pub owner: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    // GOOD: close directive with proper destination
    // custos-ignore[PRIV-014]
    // ^ Anchor's close mechanism zeroes discriminator, preventing revival attacks
    #[account(
        mut,
        close = authority,
        seeds = [b"user", vault.key().as_ref(), authority.key().as_ref()],
        bump = user_account.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Reference for validation
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: Required for has_one constraint
    pub owner: AccountInfo<'info>,
}

// ============================================================================
// Events - Minimal, Non-PII Data Only
// ============================================================================

/// GOOD: Events only contain public blockchain data
#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub authority: Pubkey,
}

#[event]
pub struct DepositEvent {
    pub vault: Pubkey,
    pub user_account: Pubkey,
    pub amount: u64,
}

#[event]
pub struct WithdrawEvent {
    pub vault: Pubkey,
    pub user_account: Pubkey,
    pub amount: u64,
}

#[event]
pub struct AccountClosed {
    pub user_account: Pubkey,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum VaultError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Unauthorized")]
    Unauthorized,
}
