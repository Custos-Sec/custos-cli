//! Wormhole-Pattern Vulnerability Demo
//!
//! This program demonstrates the EXACT CLASS of bugs that caused:
//! - Wormhole Bridge: $326M loss (Feb 2022)
//! - Cashio: $52M loss (March 2022)
//! - Crema Finance: $8.8M loss (July 2022)
//!
//! The vulnerability: Missing account initialization/validation checks
//! that allow attackers to use uninitialized or fake accounts.
//!
//! Custos detects these as PRIV-008: Uninitialized Account State

use anchor_lang::prelude::*;

declare_id!("Worm111111111111111111111111111111111111111");

#[program]
pub mod wormhole_pattern_vuln {
    use super::*;

    // ========================================================================
    // VULNERABILITY 1: Missing discriminator validation (Wormhole-style)
    // ========================================================================

    /// Process a message using guardian signatures
    ///
    /// VULNERABLE: This is the EXACT pattern that caused the $326M Wormhole hack.
    /// The guardian_set account is read via raw byte access without validating
    /// the discriminator, allowing attackers to pass ANY account with arbitrary data.
    pub fn verify_signatures(ctx: Context<VerifySignatures>) -> Result<()> {
        // VULNERABLE: Manual byte access without discriminator check
        // An attacker can pass ANY account and we'll read garbage data
        let data = ctx.accounts.guardian_set.try_borrow_data()?;

        // Reading raw bytes at fixed offsets - classic vulnerability
        // If this isn't actually a GuardianSet account, we read garbage
        let guardian_count = data[8]; // Assume first byte after discriminator
        let threshold = data[9];

        msg!("Guardian count: {}, threshold: {}", guardian_count, threshold);

        // PRIVACY LEAK: If account contains stale PII from previous owner,
        // we just logged it to the public transaction log

        // Fake "verification" that always passes due to garbage data
        if guardian_count > 0 {
            msg!("Signatures verified!"); // Always "verified" with fake data
        }

        Ok(())
    }

    // ========================================================================
    // VULNERABILITY 2: Mutable account without validation (Cashio-style)
    // ========================================================================

    /// Mint tokens using collateral
    ///
    /// VULNERABLE: The collateral account is mutable but has NO validation.
    /// Attacker can pass a fake collateral account with inflated values.
    pub fn mint_with_collateral(
        ctx: Context<MintWithCollateral>,
        amount: u64,
    ) -> Result<()> {
        // VULNERABLE: Reading from unvalidated account
        // If this isn't real collateral, we mint tokens backed by nothing
        let collateral = &ctx.accounts.collateral;

        // Directly access fields without checking account type
        let _collateral_value = collateral.value;

        // This would mint tokens based on fake collateral
        msg!("Minting {} tokens backed by {} collateral", amount, collateral.value);

        emit!(MintEvent {
            minter: ctx.accounts.authority.key(),
            amount,
            collateral_value: collateral.value,
        });

        Ok(())
    }

    // ========================================================================
    // VULNERABILITY 3: Account close without discriminator zeroing
    // ========================================================================

    /// Close a user account and return rent
    ///
    /// VULNERABLE: Account can be "revived" after close because we don't
    /// zero the discriminator. Combined with missing init check, this allows
    /// reading stale data from closed accounts.
    pub fn close_account(ctx: Context<CloseUserAccount>) -> Result<()> {
        let user_account = &ctx.accounts.user_account;

        // Log user data before closing - PRIVACY LEAK if this is stale data
        msg!("Closing account with {} tokens", user_account.balance);

        // Transfer lamports but DON'T zero discriminator
        // This account can be "revived" and read again
        let lamports = ctx.accounts.user_account.to_account_info().lamports();
        **ctx.accounts.user_account.to_account_info().try_borrow_mut_lamports()? = 0;
        **ctx.accounts.authority.to_account_info().try_borrow_mut_lamports()? += lamports;

        Ok(())
    }

    // ========================================================================
    // VULNERABILITY 4: init_if_needed without ownership check
    // ========================================================================

    /// Update user profile - can reinitialize existing accounts!
    ///
    /// VULNERABLE: init_if_needed without constraint allows attacker to
    /// reinitialize ANY existing account, potentially reading stale PII.
    pub fn update_profile(
        ctx: Context<UpdateProfile>,
        user_data: String,
    ) -> Result<()> {
        let profile = &mut ctx.accounts.user_profile;

        // If this was someone else's account, we just overwrote their data
        // But we might have READ their data first (privacy leak!)
        msg!("Previous data: {:?}", profile.data);

        profile.data = user_data;
        profile.owner = ctx.accounts.authority.key();

        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

/// Guardian set for signature verification
/// In Wormhole, attackers passed accounts that weren't actually GuardianSets
#[account]
pub struct GuardianSet {
    pub index: u32,
    pub keys: Vec<[u8; 20]>,
    pub creation_time: u32,
    pub expiration_time: u32,
}

/// Collateral account - in Cashio, fake collateral was accepted
#[account]
pub struct Collateral {
    pub mint: Pubkey,
    pub value: u64,
    pub owner: Pubkey,
}

/// User account for tracking balances
#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub last_update: i64,
}

/// User profile that might contain PII
#[account]
pub struct UserProfile {
    pub owner: Pubkey,
    pub data: String,
    pub created_at: i64,
}

// ============================================================================
// Context Structures - VULNERABLE PATTERNS
// ============================================================================

/// VULNERABLE: guardian_set uses AccountInfo without type validation
#[derive(Accounts)]
pub struct VerifySignatures<'info> {
    /// CHECK: VULNERABLE - No type validation, no discriminator check!
    /// This is the EXACT bug from Wormhole - we accept ANY account
    pub guardian_set: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

/// VULNERABLE: Collateral account is mutable without validation
#[derive(Accounts)]
pub struct MintWithCollateral<'info> {
    // VULNERABLE: mut without init, seeds, has_one, or constraint
    // Attacker can pass ANY account that deserializes as Collateral
    #[account(mut)]
    pub collateral: Account<'info, Collateral>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// VULNERABLE: user_account closed without zeroing discriminator
#[derive(Accounts)]
pub struct CloseUserAccount<'info> {
    // VULNERABLE: mut without proper close directive
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

/// VULNERABLE: init_if_needed without ownership constraint
#[derive(Accounts)]
pub struct UpdateProfile<'info> {
    // VULNERABLE: init_if_needed can reinitialize existing accounts
    // No constraint to verify ownership before update
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 256 + 8
    )]
    pub user_profile: Account<'info, UserProfile>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct MintEvent {
    pub minter: Pubkey,
    pub amount: u64,
    pub collateral_value: u64,
}

// ============================================================================
// Summary of Vulnerabilities Demonstrated
// ============================================================================
//
// 1. PRIV-008 (try_borrow_data): Manual byte access without discriminator validation
//    -> Wormhole lost $326M to this exact pattern
//
// 2. PRIV-008 (#[account(mut)]): Mutable account without init/has_one/constraint
//    -> Cashio lost $52M to fake collateral accounts
//
// 3. PRIV-014 (close without discriminator zeroing): Account revival attack
//    -> Allows reading stale PII from "closed" accounts
//
// 4. PRIV-015 (init_if_needed without constraint): Reinitialization attack
//    -> Attacker can reinitialize accounts and read previous owner's data
//
// The Privacy Impact:
// - Unvalidated accounts may contain PII from previous owners
// - Logging unvalidated data exposes that PII to public transaction logs
// - Account revival attacks expose data that users thought was deleted
// - Reinitialization attacks can expose data across user boundaries
