//! Vulnerable KYC Vault - A Privacy-Nightmare Anchor Program
//!
//! This program demonstrates WHAT NOT TO DO:
//! - Stores PII on-chain (email, phone, name)
//! - Logs sensitive user data
//! - Emits events with personal information
//! - Uses predictable PDA seeds (enumerable)
//! - No proper sanitization of user input

use anchor_lang::prelude::*;

declare_id!("Vuln111111111111111111111111111111111111111");

#[program]
pub mod vulnerable_kyc_vault {
    use super::*;

    /// Register a new user - BAD: stores and logs PII
    pub fn register_user(
        ctx: Context<RegisterUser>,
        email: String,
        phone: String,
        full_name: String,
    ) -> Result<()> {
        let user_profile = &mut ctx.accounts.user_profile;

        // BAD: Storing PII directly on-chain
        user_profile.email = email.clone();
        user_profile.phone = phone.clone();
        user_profile.full_name = full_name.clone();
        user_profile.owner = ctx.accounts.user.key();
        user_profile.is_verified = false;

        // BAD: Logging sensitive data - taint flow detected!
        msg!("New user registered: {} with email {}", full_name, email);
        msg!("Phone number: {}", phone);

        // BAD: Emitting event with full PII
        emit!(UserRegistered {
            user: ctx.accounts.user.key(),
            email: email,
            full_name: full_name,
            phone: phone,
        });

        Ok(())
    }

    /// Verify user KYC - BAD: processes and logs sensitive documents
    pub fn verify_kyc(
        ctx: Context<VerifyKyc>,
        ssn_hash: String,
        document_data: Vec<u8>,
    ) -> Result<()> {
        let user_profile = &mut ctx.accounts.user_profile;

        // BAD: Logging document data
        msg!("Processing KYC for user: {}", user_profile.email);
        msg!("Document bytes: {:?}", document_data);

        // Store the "hash" (but log the input!)
        user_profile.kyc_hash = ssn_hash.clone();
        user_profile.is_verified = true;

        // BAD: Event exposes verification details
        emit!(KycVerified {
            user: user_profile.owner,
            email: user_profile.email.clone(),
            ssn_indicator: ssn_hash,
        });

        Ok(())
    }

    /// Transfer funds - BAD: logs transaction details with user info
    pub fn transfer(
        ctx: Context<Transfer>,
        amount: u64,
        recipient_email: String,
    ) -> Result<()> {
        let sender = &ctx.accounts.sender_profile;

        // BAD: Logging sender and recipient PII
        msg!(
            "Transfer from {} ({}) to {}",
            sender.full_name,
            sender.email,
            recipient_email
        );
        msg!("Amount: {} lamports", amount);

        // BAD: Event with both parties' info
        emit!(TransferEvent {
            from_email: sender.email.clone(),
            to_email: recipient_email,
            amount,
            sender_name: sender.full_name.clone(),
        });

        Ok(())
    }

    /// Get user data via CPI - BAD: passes PII to external program
    pub fn sync_user_data(ctx: Context<SyncData>, external_data: Vec<u8>) -> Result<()> {
        let user = &ctx.accounts.user_profile;

        // BAD: Sending PII through CPI
        let user_data_for_cpi = format!(
            "{}|{}|{}",
            user.email,
            user.phone,
            user.full_name
        );

        msg!("Syncing user data: {}", user_data_for_cpi);

        // BAD: External data logged without sanitization
        msg!("Received external data: {:?}", external_data);

        Ok(())
    }
}

// ============================================================================
// Account Structures - BAD: Stores PII On-Chain
// ============================================================================

/// User profile - BAD: Full PII stored on-chain
#[account]
pub struct UserProfile {
    /// User's email address - BAD: PII on-chain
    pub email: String,
    /// User's phone number - BAD: PII on-chain
    pub phone: String,
    /// User's full legal name - BAD: PII on-chain
    pub full_name: String,
    /// Owner pubkey
    pub owner: Pubkey,
    /// KYC verification status
    pub is_verified: bool,
    /// KYC document hash
    pub kyc_hash: String,
}

// ============================================================================
// Context Structures
// ============================================================================

#[derive(Accounts)]
pub struct RegisterUser<'info> {
    // BAD: Predictable seeds allow enumeration
    #[account(
        init,
        payer = user,
        space = 8 + 64 + 32 + 64 + 32 + 1 + 64,
        seeds = [b"user_profile", user.key().as_ref()],
        bump
    )]
    pub user_profile: Account<'info, UserProfile>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyKyc<'info> {
    #[account(
        mut,
        seeds = [b"user_profile", user.key().as_ref()],
        bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub user_profile: Account<'info, UserProfile>,

    #[account(mut)]
    pub user: Signer<'info>,

    /// CHECK: For has_one
    pub owner: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(
        mut,
        seeds = [b"user_profile", sender.key().as_ref()],
        bump
    )]
    pub sender_profile: Account<'info, UserProfile>,

    #[account(mut)]
    pub sender: Signer<'info>,
}

#[derive(Accounts)]
pub struct SyncData<'info> {
    #[account(
        mut,
        seeds = [b"user_profile", user.key().as_ref()],
        bump
    )]
    pub user_profile: Account<'info, UserProfile>,

    #[account(mut)]
    pub user: Signer<'info>,
}

// ============================================================================
// Events - BAD: Emit PII
// ============================================================================

/// BAD: Event exposes full user PII
#[event]
pub struct UserRegistered {
    pub user: Pubkey,
    pub email: String,
    pub full_name: String,
    pub phone: String,
}

/// BAD: Event exposes KYC details
#[event]
pub struct KycVerified {
    pub user: Pubkey,
    pub email: String,
    pub ssn_indicator: String,
}

/// BAD: Event exposes both parties' PII
#[event]
pub struct TransferEvent {
    pub from_email: String,
    pub to_email: String,
    pub amount: u64,
    pub sender_name: String,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
}
