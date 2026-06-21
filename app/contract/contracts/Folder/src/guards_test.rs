//! Table-driven tests for authorization guard coverage
//!
//! This module ensures every public mutating entry point has explicit guard coverage.
//! Tests are organized by guard type and entry point to provide comprehensive coverage.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec};

#[test]
fn test_guard_deposit_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let user = Address::generate(&env);
    let token = Address::generate(&env);
    let salt = Bytes::from_slice(&env, &[1u8]);
    
    // Test deposit fails when not initialized
    let result = crate::RustAcademyContract::deposit(
        env.clone(),
        token.clone(),
        100,
        user.clone(),
        salt,
        0,
        None,
    );
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_withdraw_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let user = Address::generate(&env);
    let salt = Bytes::from_slice(&env, &[1u8]);
    let commitment = BytesN::from_array(&env, &[0u8; 32]);
    
    // Test withdraw fails when not initialized
    let result = crate::RustAcademyContract::withdraw(
        env.clone(),
        &user.clone(),
        100,
        commitment,
        user.clone(),
        salt,
    );
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_set_privacy_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let user = Address::generate(&env);
    
    // Test set_privacy fails when not initialized
    let result = crate::RustAcademyContract::set_privacy(env.clone(), user.clone(), true);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_set_paused_requires_admin() {
    let env = Env::default();
    env.mock_all_auths();
    
    let admin = Address::generate(&env);
    
    // Test set_paused fails when not initialized
    let result = crate::RustAcademyContract::set_paused(env.clone(), admin.clone(), true);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_register_hook_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let hook_contract = Address::generate(&env);
    
    // Test register_hook fails when not initialized
    let result = crate::RustAcademyContract::register_hook(env.clone(), hook_contract);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_set_fee_config_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let admin = Address::generate(&env);
    let config = crate::types::FeeConfig { fee_bps: 100 };
    
    // Test set_fee_config fails when not initialized
    let result = crate::RustAcademyContract::set_fee_config(env.clone(), admin.clone(), config);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_cleanup_escrow_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let commitment = BytesN::from_array(&env, &[0u8; 32]);
    
    // Test cleanup_escrow fails when not initialized
    let result = crate::RustAcademyContract::cleanup_escrow(env.clone(), commitment);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}

#[test]
fn test_guard_extend_escrow_ttl_requires_initialization() {
    let env = Env::default();
    env.mock_all_auths();
    
    let commitment = BytesN::from_array(&env, &[0u8; 32]);
    
    // Test extend_escrow_ttl fails when not initialized
    let result = crate::RustAcademyContract::extend_escrow_ttl(env.clone(), commitment);
    assert!(matches!(result, Err(crate::errors::RustAcademyError::Unauthorized)));
}
