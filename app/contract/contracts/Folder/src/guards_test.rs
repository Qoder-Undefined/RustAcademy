//! Table-driven tests for authorization guard coverage
//!
//! This module ensures every public mutating entry point has explicit guard coverage.
//! Tests are organized by guard type and entry point to provide comprehensive coverage.

#![cfg(test)]

use crate::test::*;
use soroban_sdk::{Address, Bytes, BytesN, Env};

/// Test case structure for table-driven guard tests
struct GuardTestCase {
    name: &'static str,
    setup: fn(&Env) -> (Address, Address, Address), // (admin, user, token)
    test: fn(&Env, &Address, &Address, &Address) -> Result<(), crate::errors::RustAcademyError>,
    expected_error_when_uninitialized: Option<crate::errors::RustAcademyError>,
    expected_error_when_paused: Option<crate::errors::RustAcademyError>,
    expected_error_when_emergency: Option<crate::errors::RustAcademyError>,
}

#[test]
fn test_guard_coverage_deposit_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    // Test deposit operations require initialization
    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "deposit",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, token| {
                let salt = Bytes::from_slice(env, &[1u8]);
                crate::RustAcademyContract::deposit(
                    env.clone(),
                    token.clone(),
                    100,
                    user.clone(),
                    salt,
                    0,
                    None,
                )
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcemyError::ContractPaused),
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "deposit_with_commitment",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::deposit_with_commitment(
                    env.clone(),
                    user.clone(),
                    token.clone(),
                    100,
                    commitment,
                    0,
                    None,
                )
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "deposit_partial",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, token| {
                let salt = Bytes::from_slice(env, &[1u8]);
                crate::RustAcademyContract::deposit_partial(
                    env.clone(),
                    token.clone(),
                    200,
                    100,
                    user.clone(),
                    salt,
                    0,
                    None,
                )
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "partial_payment",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::partial_payment(
                    env.clone(),
                    commitment,
                    user.clone(),
                    50,
                )
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_withdrawal_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "withdraw",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, _token| {
                let salt = Bytes::from_slice(env, &[1u8]);
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::withdraw(
                    env.clone(),
                    &user.clone(),
                    100,
                    commitment,
                    user.clone(),
                    salt,
                )
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: None, // Withdraw doesn't check emergency mode
        },
        GuardTestCase {
            name: "refund",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, _token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::refund(env.clone(), commitment, user.clone())
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: None, // Refund doesn't check emergency mode
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_admin_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "set_paused",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, admin, _user, _token| {
                crate::RustAcademyContract::set_paused(env.clone(), admin.clone(), true)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "set_admin",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, admin, _user, _token| {
                let new_admin = Address::generate(env);
                crate::RustAcademyContract::set_admin(env.clone(), admin.clone(), new_admin)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "pause_features",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, admin, _user, _token| {
                crate::RustAcademyContract::pause_features(env.clone(), admin.clone(), 1)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: Some(crate::errors::RustAcademyError::ContractPaused),
        },
        GuardTestCase {
            name: "set_fee_config",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, admin, _user, _token| {
                let config = crate::types::FeeConfig { fee_bps: 100 };
                crate::RustAcademyContract::set_fee_config(env.clone(), admin.clone(), config)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
        GuardTestCase {
            name: "set_platform_wallet",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, admin, _user, _token| {
                let wallet = Address::generate(env);
                crate::RustAcademyContract::set_platform_wallet(env.clone(), admin.clone(), wallet)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_dispute_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "dispute",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, _user, _token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::dispute(env.clone(), commitment)
            },
            expected_error_when_uninitialized: None,
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: None,
        },
        GuardTestCase {
            name: "resolve_dispute",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, _token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                let recipient = Address::generate(env);
                crate::RustAcademyContract::resolve_dispute(
                    env.clone(),
                    user.clone(),
                    commitment,
                    true,
                    recipient,
                )
            },
            expected_error_when_uninitialized: None,
            expected_error_when_paused: Some(crate::errors::RustAcademyError::ContractPaused),
            expected_error_when_emergency: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test paused state
        if let Some(expected_error) = test_case.expected_error_when_paused {
            // Initialize contract
            let (admin, user, token) = (test_case.setup)(&env);
            crate::RustAcademyContract::initialize(env.clone(), admin.clone()).unwrap();
            
            // Set paused
            crate::RustAcademyContract::set_paused(env.clone(), admin.clone(), true).unwrap();
            
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when paused",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_hook_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "register_hook",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, _user, _token| {
                let hook_contract = Address::generate(env);
                crate::RustAcademyContract::register_hook(env.clone(), hook_contract)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
        GuardTestCase {
            name: "unregister_hook",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, _user, _token| {
                let hook_contract = Address::generate(env);
                crate::RustAcademyContract::unregister_hook(env.clone(), hook_contract)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_privacy_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "set_privacy",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, user, _token| {
                crate::RustAcademyContract::set_privacy(env.clone(), user.clone(), true)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}

#[test]
fn test_guard_coverage_maintenance_operations() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = Address::generate(&env);

    let test_cases: Vec<GuardTestCase> = vec![
        GuardTestCase {
            name: "cleanup_escrow",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, _user, _token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::cleanup_escrow(env.clone(), commitment)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
        GuardTestCase {
            name: "extend_escrow_ttl",
            setup: |env| {
                let admin = Address::generate(env);
                let user = Address::generate(env);
                let token = Address::generate(env);
                (admin, user, token)
            },
            test: |env, _admin, _user, _token| {
                let commitment = BytesN::from_array(env, &[0u8; 32]);
                crate::RustAcademyContract::extend_escrow_ttl(env.clone(), commitment)
            },
            expected_error_when_uninitialized: Some(crate::errors::RustAcademyError::Unauthorized),
            expected_error_when_paused: None,
            expected_error_when_emergency: None,
        },
    ];

    for test_case in test_cases {
        println!("Testing guard coverage for: {}", test_case.name);

        // Test uninitialized state
        if let Some(expected_error) = test_case.expected_error_when_uninitialized {
            let (admin, user, token) = (test_case.setup)(&env);
            let result = (test_case.test)(&env, &admin, &user, &token);
            assert!(
                matches!(result, Err(e) if e == expected_error),
                "{} should fail with {:?} when uninitialized",
                test_case.name,
                expected_error
            );
        }
    }
}
