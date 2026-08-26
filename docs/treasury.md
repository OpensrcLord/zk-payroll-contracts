# Treasury Authorization

This document outlines the expected treasury authorization behavior during payroll execution in `zk-payroll-contracts`.

## Overview
Payroll execution requires appropriate authorization from both the company administrator (to trigger the payroll) and the company treasury (to release the funds). 

## Authorization Rules
1. **Valid Treasury Authorization**: Payroll execution must be authorized by the specific treasury account registered to the company in the `PayrollRegistry`. The execution logic pulls the `treasury` address directly from the registry and invokes a token transfer from it.
2. **Mismatched Treasury Rejection**: If an attacker or a different treasury account attempts to authorize the transfer, the token contract will reject it because the `from` address in `token.transfer(&company.treasury, &employee, &amount)` must match the authorized address.
3. **Mismatched Asset Rejection**: Only allowlisted tokens can be used for payments. If an unapproved asset is configured or attempted to be used, the execution panics with `Asset not allowed`.
4. **Stale Authorization**: Execution requires fresh proofs. Proofs older than the maximum proof age (7 days) will be rejected with a `ProofExpired` error.

## Technical Implementation
- **Company Admin Auth**: Explicitly checked via `company.admin.require_auth()`.
- **Treasury Auth**: Implicitly enforced by the token contract when `token_client.transfer(&company.treasury, ...)` is called. Soroban's auth framework requires the `company.treasury` signature to be present in the transaction auth entries.
- **Asset Allowlist**: Checked via `is_asset_allowed()`.

## Reserve Boundary Checks
The treasury must hold at least the full payment amount before payroll execution. The payment executor transfers funds before recording the payment, nullifier, period count, or running total, so an insufficient reserve fails without creating a partial payment record.

The payment executor boundary suite covers:
- An exact reserve balance, which transfers successfully and leaves the treasury at zero.
- A reserve one unit below the requested payment, which is rejected without changing balances or payment bookkeeping.
- A zero reserve for a positive payment, which is rejected without changing balances or payment bookkeeping.

Operational callers should treat an insufficient-balance failure as an actionable funding error: replenish the registered treasury and retry with the same payment inputs only after confirming the failed transaction was not committed.
