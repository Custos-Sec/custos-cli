//! Simple Uninitialized Account Demo
//!
//! This minimal program demonstrates the PRIV-008 vulnerability pattern
//! in its simplest form. Same class of bug as Wormhole ($326M), Cashio ($52M).
//!
//! The vulnerability: Accessing account data without verifying initialization.

use anchor_lang::prelude::*;

declare_id!("Simp111111111111111111111111111111111111111");

#[program]
pub mod simple_uninitialized {
    use super::*;

    /// Process user data - VULNERABLE to uninitialized account attack
    ///
    /// VULNERABLE: The config account is accessed without any validation.
    /// An attacker can pass ANY account (even one with garbage data) and
    /// this function will happily read from it.
    pub fn process_data(ctx: Context<ProcessData>) -> Result<()> {
        let config = &ctx.accounts.config;

        // CRITICAL: Direct field access without initialization check
        // This is the EXACT vulnerability class that caused:
        // - Wormhole: $326M
        // - Mango Markets: $114M
        // - Cashio: $52M
        msg!("Processing with authority: {}", config.authority);
        msg!("Config enabled: {}", config.enabled);
        msg!("Config value: {}", config.value);

        // If this account contained stale PII from a previous owner,
        // we just logged it to the PUBLIC transaction log

        Ok(())
    }

    /// Update config - VULNERABLE due to missing has_one constraint
    pub fn update_config(ctx: Context<UpdateConfig>, new_value: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // VULNERABLE: No validation that caller owns this config
        // Anyone can update anyone's config
        msg!("Previous value: {}", config.value);
        config.value = new_value;

        Ok(())
    }

    /// Withdraw based on balance - VULNERABLE to fake account attack
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let balance_account = &ctx.accounts.balance_account;

        // VULNERABLE: Reading balance from unvalidated account
        // Attacker can pass fake account with inflated balance
        msg!("Current balance: {}", balance_account.balance);

        require!(balance_account.balance >= amount, ErrorCode::InsufficientBalance);

        // Would transfer funds based on fake balance

        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub enabled: bool,
    pub value: u64,
}

#[account]
pub struct BalanceAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

// ============================================================================
// Context Structures - VULNERABLE PATTERNS
// ============================================================================

/// PRIV-008 TRIGGER: AccountInfo without type checking
#[derive(Accounts)]
pub struct ProcessData<'info> {
    /// CHECK: MISSING! No initialization validation
    /// This accepts ANY account - attacker can pass garbage data
    pub config: AccountInfo<'info>,

    pub authority: Signer<'info>,
}

/// PRIV-008 TRIGGER: Mutable Account without validation constraints
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    // VULNERABLE: mut without init, seeds, has_one, or constraint
    #[account(mut)]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub payer: Signer<'info>,
}

/// PRIV-008 TRIGGER: Reading from unvalidated account
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // VULNERABLE: No ownership validation
    // Attacker creates fake BalanceAccount with high balance
    #[account(mut)]
    pub balance_account: Account<'info, BalanceAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient balance")]
    InsufficientBalance,
}

// ============================================================================
// Why This Matters (Privacy Impact)
// ============================================================================
//
// When programs read from unvalidated accounts:
//
// 1. STALE DATA EXPOSURE: Account may contain previous owner's data
//    - Email addresses, phone numbers, SSNs
//    - Transaction history, balances
//    - Any PII stored in that account slot
//
// 2. PUBLIC LOGGING: msg!() writes to public transaction logs
//    - Anyone can read transaction logs forever
//    - Stale PII gets permanently exposed
//
// 3. CASCADING LEAKS: Fake data propagates through the system
//    - Events emit fake data (indexed by Helius, etc.)
//    - State accounts store leaked data
//
// This is why Custos treats PRIV-008 as HIGH severity:
// It's both a SECURITY bug (exploitation) and PRIVACY bug (data exposure).
