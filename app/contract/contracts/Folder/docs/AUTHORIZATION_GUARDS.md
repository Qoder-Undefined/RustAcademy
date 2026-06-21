# Authorization Guards Guide

This document describes the standardized authorization guard patterns used across all mutating entry points in the RustAcademy contract.

## Overview

All public mutating entry points MUST use standardized guard helpers from the `guards` module. This ensures consistent security coverage and makes it easy to verify that all necessary checks are in place.

## Guard Categories

### 1. Initialization Guards

**Purpose:** Ensure the contract has been initialized before allowing operations.

**Guard:** `guards::require_initialized(&env)`

**When to use:** All operations that require the contract to be in an initialized state (most operations except `initialize` itself).

**Error:** Returns `Unauthorized` if contract is not initialized.

### 2. Emergency Mode Guards

**Purpose:** Block operations when emergency mode is active. Emergency mode is irreversible and blocks most administrative operations.

**Guard:** `guards::require_not_emergency_mode(&env)`

**When to use:** Administrative state changes (pause, admin transfer, etc.) and deposit operations.

**Error:** Returns `ContractPaused` if emergency mode is active.

**Note:** Emergency mode does NOT block withdrawals or refunds to ensure users can always recover their funds.

### 3. Pause Guards

#### Global Pause

**Guard:** `guards::require_not_paused(&env)`

**When to use:** Operations that should be blocked when the contract is globally paused.

**Error:** Returns `ContractPaused` if contract is paused.

#### Feature Pause

**Guard:** `guards::require_feature_not_paused(&env, PauseFlag::SomeFeature)`

**When to use:** Operations that should be blocked when a specific feature is paused via granular pause flags.

**Error:** Returns `OperationPaused` if the feature is paused.

#### Combined Pause Check

**Guard:** `guards::require_not_paused_any(&env, PauseFlag::SomeFeature)`

**When to use:** Convenience guard that checks both global pause and feature pause.

### 4. Reentrancy Guards

**Guard:** `guards::assert_not_reentrant(&env)`

**When to use:** All operations that could be called during hook execution to prevent reentrancy attacks.

**Error:** Returns `ReentrancyDetected` if a reentrancy guard is currently set.

### 5. Role Guards

#### Single Role

**Guard:** `guards::require_role(&env, &caller, Role::Admin)`

**When to use:** Operations that require a specific role.

**Error:** Returns `InsufficientRole` if caller lacks the required role.

#### Multiple Roles

**Guard:** `guards::require_any_role(&env, &caller, &[Role::Admin, Role::Operator])`

**When to use:** Operations that can be performed by users with any of several roles.

**Error:** Returns `InsufficientRole` if caller lacks all required roles.

#### Admin Guard

**Guard:** `guards::require_admin(&env, &caller)`

**When to use:** Administrative operations that require admin role.

**Error:** Returns `InsufficientRole` if caller is not an admin.

### 6. Auth Guards

**Guard:** `guards::require_auth(&caller)`

**When to use:** When you need to explicitly require caller authorization (usually handled by Soroban's auth system automatically).

## Composite Guards

The `guards` module provides composite guards for common patterns:

### `guard_deposit`

**Checks:** Emergency mode, global pause, feature pause, reentrancy

**When to use:** All deposit operations (deposit, deposit_with_commitment, deposit_partial, partial_payment)

**Signature:** `guards::guard_deposit(&env, PauseFlag::Deposit)?`

### `guard_withdraw`

**Checks:** Global pause, feature pause, reentrancy

**When to use:** All withdrawal operations (withdraw, refund)

**Signature:** `guards::guard_withdraw(&env, PauseFlag::Withdrawal)?`

**Note:** Does NOT check emergency mode to ensure users can always withdraw funds.

### `guard_admin_operation`

**Checks:** Emergency mode, initialization, admin role

**When to use:** Administrative operations that require full admin access

**Signature:** `guards::guard_admin_operation(&env, &caller)?`

### `guard_operator_operation`

**Checks:** Emergency mode, initialization, admin or operator role

**When to use:** Operations that can be performed by admins or operators

**Signature:** `guards::guard_operator_operation(&env, &caller)?`

### `guard_admin_state_change`

**Checks:** Emergency mode, admin role

**When to use:** Administrative state changes (pause, admin transfer, etc.)

**Signature:** `guards::guard_admin_state_change(&env, &caller)?`

### `guard_dispute`

**Checks:** Global pause, reentrancy

**When to use:** Dispute-related operations

**Signature:** `guards::guard_dispute(&env)?`

### `guard_hook_registration`

**Checks:** Initialization, reentrancy

**When to use:** Hook registration/unregistration

**Signature:** `guards::guard_hook_registration(&env)?`

### `guard_fee_config`

**Checks:** Reentrancy, admin or operator role

**When to use:** Fee configuration changes

**Signature:** `guards::guard_fee_config(&env, &caller)?`

## Guard Selection Guide

### Deposit Operations

Use `guard_deposit` for:
- `deposit`
- `deposit_with_commitment`
- `deposit_partial`
- `partial_payment`

**Rationale:** Deposits should be blocked in emergency mode, when paused, and must check reentrancy.

### Withdrawal Operations

Use `guard_withdraw` for:
- `withdraw`
- `refund`

**Rationale:** Withdrawals should NOT be blocked in emergency mode (users must always be able to recover funds), but should check pause and reentrancy.

### Administrative Operations

Use `guard_admin_state_change` for:
- `set_paused`
- `pause_features`
- `unpause_features`
- `set_admin`

**Rationale:** These are state changes that require admin role and should be blocked in emergency mode.

Use `guard_admin_operation` for:
- `set_platform_wallet`
- `rotate_fee_collector`

**Rationale:** These require admin role and initialization, and should be blocked in emergency mode.

Use `guard_operator_operation` for:
- Operations that admins or operators can perform

**Rationale:** These require either admin or operator role and initialization.

### Fee Configuration

Use `guard_fee_config` for:
- `set_fee_config`
- `set_per_asset_fee`
- `set_oracle_fee_config`

**Rationale:** Fee config changes require admin/operator role and reentrancy check.

### Dispute Operations

Use `guard_dispute` for:
- `dispute`
- `resolve_dispute`
- `vote_for_dispute`
- `resolve_dispute_multi_sig`

**Rationale:** Dispute operations should be blocked when paused and must check reentrancy.

### Hook Operations

Use `guard_hook_registration` for:
- `register_hook`
- `unregister_hook`

**Rationale:** Hook operations require initialization and reentrancy check.

### Privacy Operations

Use `require_initialized` for:
- `set_privacy`

**Rationale:** Privacy settings require initialization but don't need pause/emergency checks.

### Maintenance Operations

Use `require_initialized` for:
- `cleanup_escrow`
- `extend_escrow_ttl`

**Rationale:** Maintenance operations require initialization but are user operations that don't need pause/emergency checks.

### Emergency Mode

Use `require_admin` for:
- `activate_emergency_mode`

**Rationale:** Only admin can activate emergency mode, and this operation itself is not blocked by emergency mode.

## Adding a New Mutating Entry Point

When adding a new public mutating entry point, follow this checklist:

1. **Determine the operation type:**
   - Is it a deposit? → Use `guard_deposit`
   - Is it a withdrawal? → Use `guard_withdraw`
   - Is it an admin state change? → Use `guard_admin_state_change`
   - Is it an admin operation? → Use `guard_admin_operation`
   - Is it an operator operation? → Use `guard_operator_operation`
   - Is it a fee config change? → Use `guard_fee_config`
   - Is it a dispute operation? → Use `guard_dispute`
   - Is it a hook operation? → Use `guard_hook_registration`
   - Is it a user operation requiring initialization? → Use `require_initialized`

2. **Add the guard at the start of the function:**
   ```rust
   pub fn my_new_function(env: Env, caller: Address, ...) -> Result<(), RustAcademyError> {
       guards::guard_deposit(&env, PauseFlag::Deposit)?;
       // ... rest of function
   }
   ```

3. **Add a test case in `guards_test.rs`:**
   - Add your function to the appropriate test case table
   - Specify expected errors for uninitialized, paused, and emergency states
   - Run the tests to verify guard coverage

4. **Update this document:**
   - If you created a new operation type, document it here
   - If you used an existing guard type, ensure it's listed in the appropriate section

## Testing Guard Coverage

The contract includes a table-driven test suite (`guards_test.rs`) that verifies every public mutating entry point has appropriate guard coverage.

To run the guard tests:
```bash
cargo test guards_test
```

The tests verify:
- Operations fail with appropriate errors when contract is not initialized
- Operations fail with appropriate errors when contract is paused
- Operations fail with appropriate errors when emergency mode is active (where applicable)

## Emergency Mode Behavior

Emergency mode is a special state that:
- Is irreversible once activated
- Blocks most administrative operations
- Does NOT block withdrawals or refunds (users must always recover funds)
- Blocks deposit operations

This design ensures that in an emergency, users can always recover their funds while preventing further deposits and administrative changes.

## Migration Guide

If you're updating existing code to use the new guard system:

1. **Identify the current guard pattern:**
   - Look for manual checks like `if admin::is_paused(&env)`
   - Look for `admin::require_initialized(&env)`
   - Look for `hook::assert_not_reentrant(&env)`
   - Look for `storage::is_emergency_mode(&env)`

2. **Replace with the appropriate composite guard:**
   - Multiple checks → Use the appropriate composite guard
   - Single check → Use the individual guard function

3. **Test the changes:**
   - Run the guard tests to verify coverage
   - Run the full test suite to ensure no regressions

## Examples

### Example 1: Deposit Operation

**Before:**
```rust
pub fn deposit(env: Env, ...) -> Result<BytesN<32>, RustAcademyError> {
    if storage::is_emergency_mode(&env) {
        return Err(RustAcademyError::ContractPaused);
    }
    if admin::is_paused(&env) {
        return Err(RustAcademyError::ContractPaused);
    }
    if is_feature_paused(&env, PauseFlag::Deposit) {
        return Err(RustAcademyError::OperationPaused);
    }
    hook::assert_not_reentrant(&env)?;
    // ... rest of function
}
```

**After:**
```rust
pub fn deposit(env: Env, ...) -> Result<BytesN<32>, RustAcademyError> {
    guards::guard_deposit(&env, PauseFlag::Deposit)?;
    // ... rest of function
}
```

### Example 2: Admin Operation

**Before:**
```rust
pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), RustAcademyError> {
    if storage::is_emergency_mode(&env) {
        return Err(RustAcademyError::ContractPaused);
    }
    admin::set_admin(&env, caller, new_admin)
}
```

**After:**
```rust
pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), RustAcademyError> {
    guards::guard_admin_state_change(&env, &caller)?;
    admin::set_admin(&env, caller, new_admin)
}
```

### Example 3: User Operation Requiring Initialization

**Before:**
```rust
pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), RustAcademyError> {
    admin::require_initialized(&env)?;
    privacy::set_privacy(&env, owner, enabled)
}
```

**After:**
```rust
pub fn set_privacy(env: Env, owner: Address, enabled: bool) -> Result<(), RustAcademyError> {
    guards::require_initialized(&env)?;
    privacy::set_privacy(&env, owner, enabled)
}
```

## Troubleshooting

### My operation is failing with Unauthorized

**Cause:** The contract is not initialized.

**Solution:** Ensure the contract has been initialized via `initialize()` before calling your operation. If your operation should work without initialization, remove the `require_initialized` guard.

### My operation is failing with ContractPaused

**Cause:** The contract is paused or emergency mode is active.

**Solution:** 
- If the operation should work when paused, remove the pause guard
- If the operation should work in emergency mode, remove the emergency mode guard
- For withdrawals, use `guard_withdraw` instead of `guard_deposit` to allow emergency mode withdrawals

### My operation is failing with OperationPaused

**Cause:** A specific feature flag is paused.

**Solution:** Either unpause the feature or remove the feature pause guard if the operation should work when the feature is paused.

### My operation is failing with ReentrancyDetected

**Cause:** The operation is being called reentrantly during hook execution.

**Solution:** This is expected behavior for operations called during hooks. If your operation needs to be callable during hooks, remove the reentrancy guard (but be careful of reentrancy attacks).

## Best Practices

1. **Always use guards:** Every mutating entry point should have appropriate guards
2. **Use composite guards:** Prefer composite guards over individual checks for common patterns
3. **Test guard coverage:** Add test cases to `guards_test.rs` for new operations
4. **Document exceptions:** If an operation intentionally bypasses a guard, document why
5. **Consider emergency mode:** Ensure users can always withdraw funds in emergency mode
6. **Be consistent:** Use the same guard pattern for similar operations

## Related Documentation

- [Guards Module](../src/guards.rs) - Implementation of guard helpers
- [Guard Tests](../src/guards_test.rs) - Table-driven guard coverage tests
- [Storage Module](../src/storage.rs) - Storage and pause flag definitions
- [Admin Module](../src/admin.rs) - Admin and role management
