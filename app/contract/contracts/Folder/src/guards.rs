//! # Authorization Guards
//!
//! This module provides shared guard helpers for normalizing authorization requirements
//! across all mutating entry points in the contract.
//!
//! ## Guard Categories
//!
//! - **Initialization guards**: Ensure contract is initialized before operations
//! - **Emergency mode guards**: Block operations when emergency mode is active
//! - **Pause guards**: Block operations when contract or features are paused
//! - **Reentrancy guards**: Prevent reentrant calls during hook execution
//! - **Role guards**: Ensure caller has required role
//! - **Auth guards**: Ensure caller authorization
//!
//! ## Usage Pattern
//!
//! Every public mutating entry point should use guards consistently:
//!
//! ```rust
//! pub fn some_mutation(env: Env, caller: Address, ...) -> Result<(), RustAcademyError> {
//!     // 1. Check emergency mode (if applicable)
//!     guards::require_not_emergency_mode(&env)?;
//!
//!     // 2. Check global pause (if applicable)
//!     guards::require_not_paused(&env)?;
//!
//!     // 3. Check feature pause (if applicable)
//!     guards::require_feature_not_paused(&env, PauseFlag::SomeFeature)?;
//!
//!     // 4. Check reentrancy (if applicable)
//!     guards::assert_not_reentrant(&env)?;
//!
//!     // 5. Check initialization (if applicable)
//!     guards::require_initialized(&env)?;
//!
//!     // 6. Check role/auth (if applicable)
//!     guards::require_role(&env, &caller, Role::Admin)?;
//!
//!     // ... proceed with business logic
//! }
//! ```

use crate::admin;
use crate::errors::RustAcademyError;
use crate::hook;
use crate::storage::{self, PauseFlag};
use crate::types::Role;
use soroban_sdk::{Address, Env};

// ---------------------------------------------------------------------------
// Initialization Guards
// ---------------------------------------------------------------------------

/// Require that the contract has been initialized.
///
/// Returns `Unauthorized` if the contract has not been initialized.
pub fn require_initialized(env: &Env) -> Result<(), RustAcademyError> {
    admin::require_initialized(env)
}

// ---------------------------------------------------------------------------
// Emergency Mode Guards
// ---------------------------------------------------------------------------

/// Require that emergency mode is NOT active.
///
/// Emergency mode is irreversible and blocks most operations when active.
/// Returns `ContractPaused` if emergency mode is active.
pub fn require_not_emergency_mode(env: &Env) -> Result<(), RustAcademyError> {
    if storage::is_emergency_mode(env) {
        return Err(RustAcademyError::ContractPaused);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pause Guards
// ---------------------------------------------------------------------------

/// Require that the contract is NOT globally paused.
///
/// Returns `ContractPaused` if the contract is paused.
pub fn require_not_paused(env: &Env) -> Result<(), RustAcademyError> {
    if admin::is_paused(env) {
        return Err(RustAcademyError::ContractPaused);
    }
    Ok(())
}

/// Require that a specific feature is NOT paused.
///
/// Returns `OperationPaused` if the feature is paused via granular pause flags.
pub fn require_feature_not_paused(env: &Env, flag: PauseFlag) -> Result<(), RustAcademyError> {
    if storage::is_feature_paused(env, flag) {
        return Err(RustAcademyError::OperationPaused);
    }
    Ok(())
}

/// Require that both global pause and feature pause are not active.
///
/// Convenience guard that combines both pause checks.
pub fn require_not_paused_any(env: &Env, flag: PauseFlag) -> Result<(), RustAcademyError> {
    require_not_paused(env)?;
    require_feature_not_paused(env, flag)
}

// ---------------------------------------------------------------------------
// Reentrancy Guards
// ---------------------------------------------------------------------------

/// Require that the call is not reentrant.
///
/// Returns `ReentrancyDetected` if a reentrancy guard is currently set.
pub fn assert_not_reentrant(env: &Env) -> Result<(), RustAcademyError> {
    hook::assert_not_reentrant(env)
}

// ---------------------------------------------------------------------------
// Role Guards
// ---------------------------------------------------------------------------

/// Require that the caller has a specific role.
///
/// Returns `InsufficientRole` if the caller lacks the required role.
pub fn require_role(env: &Env, caller: &Address, role: Role) -> Result<(), RustAcademyError> {
    admin::require_any_role(env, caller, &[role])
}

/// Require that the caller has at least one of the specified roles.
///
/// Returns `InsufficientRole` if the caller lacks all required roles.
pub fn require_any_role(env: &Env, caller: &Address, roles: &[Role]) -> Result<(), RustAcademyError> {
    admin::require_any_role(env, caller, roles)
}

/// Require that the caller is an admin.
///
/// Returns `InsufficientRole` if the caller is not an admin.
pub fn require_admin(env: &Env, caller: &Address) -> Result<(), RustAcademyError> {
    admin::require_admin(env, caller)
}

// ---------------------------------------------------------------------------
// Auth Guards
// ---------------------------------------------------------------------------

/// Require that the caller authorizes the transaction.
///
/// This is a thin wrapper around `Address::require_auth()` for consistency.
pub fn require_auth(caller: &Address) {
    caller.require_auth();
}

// ---------------------------------------------------------------------------
// Composite Guards for Common Patterns
// ---------------------------------------------------------------------------

/// Standard guard for user-initiated deposit operations.
///
/// Checks: emergency mode, global pause, feature pause, reentrancy.
pub fn guard_deposit(env: &Env, flag: PauseFlag) -> Result<(), RustAcademyError> {
    require_not_emergency_mode(env)?;
    require_not_paused_any(env, flag)?;
    assert_not_reentrant(env)?;
    Ok(())
}

/// Standard guard for user-initiated withdrawal operations.
///
/// Checks: global pause, feature pause, reentrancy.
pub fn guard_withdraw(env: &Env, flag: PauseFlag) -> Result<(), RustAcademyError> {
    require_not_paused_any(env, flag)?;
    assert_not_reentrant(env)?;
    Ok(())
}

/// Standard guard for admin operations.
///
/// Checks: emergency mode, initialization, admin role.
pub fn guard_admin_operation(env: &Env, caller: &Address) -> Result<(), RustAcademyError> {
    require_not_emergency_mode(env)?;
    require_initialized(env)?;
    require_admin(env, caller)?;
    Ok(())
}

/// Standard guard for operator operations.
///
/// Checks: emergency mode, initialization, admin or operator role.
pub fn guard_operator_operation(env: &Env, caller: &Address) -> Result<(), RustAcademyError> {
    require_not_emergency_mode(env)?;
    require_initialized(env)?;
    require_any_role(env, caller, &[Role::Admin, Role::Operator])?;
    Ok(())
}

/// Standard guard for administrative state changes (pause, admin transfer, etc.).
///
/// Checks: emergency mode, admin role.
pub fn guard_admin_state_change(env: &Env, caller: &Address) -> Result<(), RustAcademyError> {
    require_not_emergency_mode(env)?;
    require_admin(env, caller)?;
    Ok(())
}

/// Standard guard for dispute operations.
///
/// Checks: global pause, reentrancy.
pub fn guard_dispute(env: &Env) -> Result<(), RustAcademyError> {
    require_not_paused(env)?;
    assert_not_reentrant(env)?;
    Ok(())
}

/// Standard guard for hook registration.
///
/// Checks: initialization, reentrancy.
pub fn guard_hook_registration(env: &Env) -> Result<(), RustAcademyError> {
    require_initialized(env)?;
    assert_not_reentrant(env)?;
    Ok(())
}

/// Standard guard for fee configuration changes.
///
/// Checks: reentrancy, admin or operator role.
pub fn guard_fee_config(env: &Env, caller: &Address) -> Result<(), RustAcademyError> {
    assert_not_reentrant(env)?;
    require_any_role(env, caller, &[Role::Admin, Role::Operator])?;
    Ok(())
}
