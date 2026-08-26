use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger as _};
use soroban_sdk::{Env, Symbol, TryIntoVal};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, soroban_sdk::Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    (env, contract_id)
}

// ---------------------------------------------------------------------------
// generate_view_key / verify_access
// ---------------------------------------------------------------------------

#[test]
fn test_generate_view_key_stores_and_verify_access_succeeds() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let current_seq = env.ledger().sequence();
    let expiration = current_seq + 1_000;

    let key_bytes = client.generate_view_key(&auditor, &expiration);

    assert_eq!(key_bytes.len(), 32);

    let after = env.events().all().len();
    assert_eq!(after, 1);

    let event = env.events().all().get(0).unwrap();
    assert_eq!(event.1.len(), 2);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "ViewKeyGenerated"));
    let addr0: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr0, auditor);

    // verify_access: auditor holds a valid key
    assert!(client.verify_access(&auditor));

    let record = client.get_view_key(&auditor);
    assert_eq!(record.key_bytes, key_bytes);
    assert_eq!(record.expiration_ledger, expiration);
}

#[test]
fn test_successive_generate_produces_unique_keys() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();

    let key_a = client.generate_view_key(&auditor, &(seq + 500));

    env.ledger().set_sequence_number(seq + 1);

    let key_b = client.generate_view_key(&auditor, &(seq + 500));

    assert_ne!(key_a, key_b, "successive keys must be distinct");

    let live = client.get_view_key(&auditor);
    assert_eq!(live.key_bytes, key_b);
}

// ---------------------------------------------------------------------------
// Expiry (ledger sequence)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_access_expired_fails() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;

    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&auditor));

    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));
}

#[test]
fn test_verify_access_no_key_returns_false() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);
    assert!(!client.verify_access(&stranger));
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn test_revoke_removes_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    assert!(client.verify_access(&auditor));

    let admin = contract_id.clone();
    let before = env.events().all().len();
    client.revoke_view_key(&admin, &auditor);
    let after = env.events().all().len();
    assert_eq!(after, before + 1);

    let event = env.events().all().get(after - 1).unwrap();
    assert_eq!(event.1.len(), 3);
    let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym0, Symbol::new(&env, "AuditAccessRevoked"));
    let addr0: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr0, admin);
    let addr1: Address = event.1.get(2).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr1, auditor);

    assert!(!client.verify_access(&auditor));

    assert!(client.try_get_view_key(&auditor).is_err());
}

#[test]
fn test_revoke_wrong_admin_fails() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let interloper = soroban_sdk::Address::generate(&env);
    assert!(client.try_revoke_view_key(&interloper, &auditor).is_err());
}

// ---------------------------------------------------------------------------
// Commitment verification
// ---------------------------------------------------------------------------

#[test]
fn test_verify_commitment_with_key_matches() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 500_000;
    let blinding = BytesN::from_array(&env, &[0xAB; 32]);

    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));

    // Wrong amount must return CommitmentMismatch error
    let result = client.try_verify_commitment_with_key(
        &auditor,
        &stored,
        &999_i128,
        &blinding,
        &AuditScope::EmployeeList,
    );
    assert!(result.is_err());
}

#[test]
fn test_verify_commitment_with_supplied_key_matches() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key = client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 120_000;
    let blinding = BytesN::from_array(&env, &[0xCD; 32]);

    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client.verify_commitment_with_view_key(
        &auditor,
        &key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));
}

#[test]
fn test_verify_commitment_with_supplied_key_rejects_wrong_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));
    let wrong_key = BytesN::from_array(&env, &[0xEE; 32]);

    let amount: i128 = 120_000;
    let blinding = BytesN::from_array(&env, &[0xCD; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client
        .try_verify_commitment_with_view_key(
            &auditor,
            &wrong_key,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList
        )
        .is_err());
}

#[test]
fn test_cross_auditor_key_contamination_is_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor_a = soroban_sdk::Address::generate(&env);
    let auditor_b = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key_a = client.generate_view_key(&auditor_a, &(seq + 1_000));
    client.generate_view_key(&auditor_b, &(seq + 1_000));

    let amount: i128 = 77_000;
    let blinding = BytesN::from_array(&env, &[0x11; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    assert!(client
        .try_verify_commitment_with_view_key(
            &auditor_b,
            &key_a,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList
        )
        .is_err());
}

#[test]
fn test_aggregate_only_scope_rejects_commitment_verification() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let dummy = BytesN::from_array(&env, &[0u8; 32]);
    assert!(client
        .try_verify_commitment_with_key(
            &auditor,
            &dummy,
            &0_i128,
            &dummy,
            &AuditScope::AggregateOnly
        )
        .is_err());
}

#[test]
fn test_successful_commitment_audit_emits_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 42_000;
    let blinding = BytesN::from_array(&env, &[0x99; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    let before = env.events().all().len();
    assert!(client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));
    let after = env.events().all().len();
    assert_eq!(after, before + 1);
}

// ---------------------------------------------------------------------------
// Aggregate report
// ---------------------------------------------------------------------------

#[test]
fn test_generate_aggregate_report_valid_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "ACME");
    let now = env.ledger().timestamp();
    let before = env.events().all().len();
    let report = client.generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400));
    let after = env.events().all().len();

    assert_eq!(report.company_id, company_id);
    assert_eq!(report.period_start, now);
    assert_eq!(after, before + 1);

    let stranger = soroban_sdk::Address::generate(&env);
    assert!(client
        .try_generate_aggregate_report(&stranger, &company_id, &now, &(now + 86_400))
        .is_err());
}

// ---------------------------------------------------------------------------
// Audit query patterns — company-level, employee-level, period-level
// ---------------------------------------------------------------------------

#[test]
fn test_query_by_company_returns_audit_log_entries() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 100_000;
    let blinding = BytesN::from_array(&env, &[0xBB; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_company(&company_id);

    assert!(!result.entries.is_empty());
}

#[test]
fn test_query_by_employee_filters_by_auditor() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 50_000;
    let blinding = BytesN::from_array(&env, &[0xCC; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_employee(&company_id, &auditor);

    assert!(!result.entries.is_empty());
}

#[test]
fn test_query_by_period_filters_by_time_range() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 75_000;
    let blinding = BytesN::from_array(&env, &[0xDD; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    let ts = env.ledger().timestamp();
    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let result = client.query_by_period(&company_id, &ts, &(ts + 10_000));

    assert!(!result.entries.is_empty());
}

#[test]
fn test_get_audit_log_count_increments() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "default");
    let count_before = client.get_audit_log_count(&company_id);

    let amount: i128 = 25_000;
    let blinding = BytesN::from_array(&env, &[0xEE; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let stored: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let count_after = client.get_audit_log_count(&company_id);
    assert!(count_after > count_before);
}

// ── Issue #93: audit metadata export ─────────────────────────────────────────

#[test]
fn test_export_audit_summary_returns_correct_counts() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    // Generate one passing and one failing audit entry.
    let amount: i128 = 10_000;
    let blinding = BytesN::from_array(&env, &[0xAA; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let correct_commitment: BytesN<32> = env.crypto().sha256(&preimage).into();

    // Pass 1: commitment verification
    client.verify_commitment_with_key(
        &auditor,
        &correct_commitment,
        &amount,
        &blinding,
        &AuditScope::FullCompany,
    );

    let company_id = Symbol::new(&env, "default");
    let ts = env.ledger().timestamp();

    // Pass 2: aggregate report generation
    let _ = client.generate_aggregate_report(&auditor, &company_id, &0u64, &(ts + 1_000));

    let summary = client.export_audit_summary(&auditor, &company_id, &0u64, &(ts + 1_000_000u64));

    assert_eq!(summary.company_id, company_id);
    assert_eq!(summary.exported_by, auditor);
    assert!(summary.total_audit_entries >= 2);
    assert!(summary.verification_pass_count >= 1);
}

#[test]
fn test_export_audit_summary_excludes_out_of_period_entries() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 5_000;
    let blinding = BytesN::from_array(&env, &[0xBB; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let commitment: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &commitment,
        &amount,
        &blinding,
        &AuditScope::FullCompany,
    );

    let company_id = Symbol::new(&env, "default");
    // Request a period that is far in the future — no entries should match.
    let far_future: u64 = 999_999_999_999;
    let summary =
        client.export_audit_summary(&auditor, &company_id, &far_future, &(far_future + 1_000));

    assert_eq!(summary.total_audit_entries, 0);
    assert_eq!(summary.verification_pass_count, 0);
    assert_eq!(summary.verification_fail_count, 0);
}

#[test]
fn test_export_audit_summary_requires_valid_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);
    let company_id = Symbol::new(&env, "default");

    // Stranger has no view key — should return KeyNotFound error.
    assert!(client
        .try_export_audit_summary(&stranger, &company_id, &0u64, &1_000u64)
        .is_err());
}

#[test]
fn test_export_audit_summary_emits_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "default");
    let ts = env.ledger().timestamp();
    let before = env.events().all().len();

    client.export_audit_summary(&auditor, &company_id, &0u64, &(ts + 1_000));

    assert!(env.events().all().len() > before);
}

// ── Issue #172: revoked audit grants cannot read/export/validate audit data ──
//
// These tests confirm that once `revoke_view_key` succeeds, every
// authorize_auditor-gated entry point rejects the former auditor with
// `AuditError::KeyNotFound` — the same failure mode as an auditor who was
// never granted a key. This is the property compliance relies on: revocation
// must immediately and completely cut off access to restricted audit data,
// with no operation left that still honors the stale grant.

fn make_commitment(env: &Env, amount: i128, blinding: &BytesN<32>) -> BytesN<32> {
    let mut preimage = soroban_sdk::Bytes::new(env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = blinding.into();
    preimage.extend_from_array(&blinding_slice);
    env.crypto().sha256(&preimage).into()
}

#[test]
fn test_revoked_key_cannot_validate_commitment_with_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 100_000;
    let blinding = BytesN::from_array(&env, &[0x21; 32]);
    let stored = make_commitment(&env, amount, &blinding);

    // Sanity check: verification succeeds while the grant is live.
    assert!(client.verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    let result = client.try_verify_commitment_with_key(
        &auditor,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_revoked_key_cannot_validate_commitment_with_supplied_view_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let key = client.generate_view_key(&auditor, &(seq + 1_000));

    let amount: i128 = 120_000;
    let blinding = BytesN::from_array(&env, &[0x22; 32]);
    let stored = make_commitment(&env, amount, &blinding);

    // Sanity check: verification succeeds while the grant is live.
    assert!(client.verify_commitment_with_view_key(
        &auditor,
        &key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    // Even presenting the still-known key bytes must fail, since the
    // underlying grant record no longer exists.
    let result = client.try_verify_commitment_with_view_key(
        &auditor,
        &key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_revoked_key_cannot_generate_aggregate_report() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "ACME");
    let now = env.ledger().timestamp();

    // Sanity check: report generation succeeds while the grant is live.
    assert!(client
        .try_generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400))
        .is_ok());

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    let result =
        client.try_generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400));
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_revoked_key_cannot_export_audit_summary() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let company_id = Symbol::new(&env, "default");
    let ts = env.ledger().timestamp();

    // Sanity check: export succeeds while the grant is live.
    assert!(client
        .try_export_audit_summary(&auditor, &company_id, &0u64, &(ts + 1_000))
        .is_ok());

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    let result = client.try_export_audit_summary(&auditor, &company_id, &0u64, &(ts + 1_000));
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_revoked_key_cannot_read_view_key_record() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    let result = client.try_get_view_key(&auditor);
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

#[test]
fn test_revocation_does_not_affect_other_auditors() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let revoked_auditor = soroban_sdk::Address::generate(&env);
    let active_auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&revoked_auditor, &(seq + 1_000));
    client.generate_view_key(&active_auditor, &(seq + 1_000));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &revoked_auditor);

    // The revoked auditor loses access...
    assert!(!client.verify_access(&revoked_auditor));
    assert!(client.try_get_view_key(&revoked_auditor).is_err());

    // ...but an unrelated auditor's grant must remain fully intact.
    assert!(client.verify_access(&active_auditor));

    let company_id = Symbol::new(&env, "ACME");
    let now = env.ledger().timestamp();
    assert!(client
        .try_generate_aggregate_report(&active_auditor, &company_id, &now, &(now + 86_400))
        .is_ok());
}

#[test]
fn test_revoke_then_regrant_restores_access() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);
    assert!(!client.verify_access(&auditor));

    // Issuing a fresh grant after revocation must restore access — a stale
    // revocation must not permanently lock the auditor out.
    let new_key = client.generate_view_key(&auditor, &(seq + 2_000));
    assert!(client.verify_access(&auditor));

    let amount: i128 = 33_000;
    let blinding = BytesN::from_array(&env, &[0x33; 32]);
    let stored = make_commitment(&env, amount, &blinding);

    assert!(client.verify_commitment_with_view_key(
        &auditor,
        &new_key,
        &stored,
        &amount,
        &blinding,
        &AuditScope::EmployeeList
    ));
}

// ── Issue #171: admin / auditor role-boundary tests ──────────────────────────
//
// FINDING: `generate_view_key` takes no caller/admin parameter and never
// calls `require_auth()` anywhere in its body — there is no admin role
// gating who may grant auditor access in this contract at all. It also
// always records `granted_by` as the contract's own address
// (`env.current_contract_address()`), never the caller, which means
// `revoke_view_key` can never be satisfied by any genuine external admin
// either (see `revoke_view_key`'s `record.granted_by != admin` check).
//
// The two tests below document this as currently-observed behavior. They
// are not an endorsement that it is correct — flagged separately for a
// follow-up fix, out of scope for this tests-only issue.

#[test]
fn test_generate_view_key_has_no_caller_authorization() {
    // Deliberately no mock_all_auths() and no mocked auths whatsoever — this
    // call succeeds even for a completely unauthenticated invocation.
    let env = Env::default();
    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    let self_appointed_auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&self_appointed_auditor, &(seq + 1_000));

    assert!(client.verify_access(&self_appointed_auditor));
}

#[test]
fn test_revoke_view_key_rejects_genuine_external_admin() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    // A real, externally-controlled address, signing legitimately —
    // still not the contract's own address stored as `granted_by`.
    let would_be_admin = soroban_sdk::Address::generate(&env);
    let result = client.try_revoke_view_key(&would_be_admin, &auditor);
    assert_eq!(result.unwrap_err().unwrap(), AuditError::NotKeyGranter);

    // The grant remains fully intact — the revocation attempt had no effect.
    assert!(client.verify_access(&auditor));
}

// ── Issue #177: metadata hash verification via audit scope ──────────────────

#[test]
fn test_verify_payroll_metadata_match_returns_true() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let hash = BytesN::from_array(&env, &[0xAA; 32]);
    let result = client.verify_payroll_metadata(
        &auditor,
        &hash,
        &hash,
        &AuditScope::FullCompany,
    );
    assert!(result.unwrap());
}

#[test]
fn test_verify_payroll_metadata_mismatch_returns_false() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let stored = BytesN::from_array(&env, &[0xBB; 32]);
    let expected = BytesN::from_array(&env, &[0xCC; 32]);
    let result = client.verify_payroll_metadata(
        &auditor,
        &stored,
        &expected,
        &AuditScope::FullCompany,
    );
    assert!(!result.unwrap());
}

#[test]
fn test_verify_payroll_metadata_records_audit_log() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let hash = BytesN::from_array(&env, &[0xDD; 32]);
    let before = client.get_audit_log_count(&Symbol::new(&env, "default"));
    let _ = client.verify_payroll_metadata(
        &auditor,
        &hash,
        &hash,
        &AuditScope::FullCompany,
    );
    let after = client.get_audit_log_count(&Symbol::new(&env, "default"));
    assert!(after > before);
}

#[test]
fn test_verify_payroll_metadata_emits_match_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let hash = BytesN::from_array(&env, &[0xEE; 32]);
    let before = env.events().all().len();
    let _ = client.verify_payroll_metadata(
        &auditor,
        &hash,
        &hash,
        &AuditScope::FullCompany,
    );
    let after = env.events().all().len();
    assert!(after > before);
}

#[test]
fn test_verify_payroll_metadata_emits_mismatch_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let stored = BytesN::from_array(&env, &[0x11; 32]);
    let expected = BytesN::from_array(&env, &[0x22; 32]);
    let before = env.events().all().len();
    let _ = client.verify_payroll_metadata(
        &auditor,
        &stored,
        &expected,
        &AuditScope::FullCompany,
    );
    let after = env.events().all().len();
    assert!(after > before);
}

#[test]
fn test_verify_payroll_metadata_requires_valid_key() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);
    let hash = BytesN::from_array(&env, &[0x33; 32]);
    let result = client.try_verify_payroll_metadata(
        &stranger,
        &hash,
        &hash,
        &AuditScope::FullCompany,
    );
    assert!(result.is_err());
}

#[test]
fn test_verify_payroll_metadata_rejects_aggregate_only_scope() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let hash = BytesN::from_array(&env, &[0x44; 32]);
    let result = client.try_verify_payroll_metadata(
        &auditor,
        &hash,
        &hash,
        &AuditScope::AggregateOnly,
    );
    assert!(result.is_err());
}

#[test]
fn test_verify_payroll_metadata_revoked_auditor_rejected() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let admin = contract_id.clone();
    client.revoke_view_key(&admin, &auditor);

    let hash = BytesN::from_array(&env, &[0x55; 32]);
    let result = client.try_verify_payroll_metadata(
        &auditor,
        &hash,
        &hash,
        &AuditScope::FullCompany,
    );
    assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
}

// ── Issue #356: stale audit grant pruning ────────────────────────────────────

// Helper: build a Vec<Address> from a slice.
fn addr_vec(env: &Env, addrs: &[soroban_sdk::Address]) -> Vec<soroban_sdk::Address> {
    let mut v = Vec::new(env);
    for a in addrs {
        v.push_back(a.clone());
    }
    v
}

// ---------------------------------------------------------------------------
// prune_expired_grants — core pruning behaviour
// ---------------------------------------------------------------------------

#[test]
fn test_prune_expired_grant_removes_key_and_blocks_access() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;
    client.generate_view_key(&auditor, &expiration);

    // Advance past expiry.
    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor), "expired key should not grant access");

    let pruned = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(pruned, 1, "one grant should be pruned");

    // Access must still be denied after pruning.
    assert!(!client.verify_access(&auditor));

    // get_view_key must return an error — the record was removed.
    assert!(client.try_get_view_key(&auditor).is_err());
}

#[test]
fn test_prune_leaves_active_grant_intact() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 1_000;
    client.generate_view_key(&auditor, &expiration);

    // Grant is still live — pruning must not touch it.
    let pruned = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(pruned, 0, "active grant must not be pruned");

    assert!(client.verify_access(&auditor));
    let record = client.get_view_key(&auditor);
    assert_eq!(record.expiration_ledger, expiration);
}

#[test]
fn test_prune_at_exact_expiry_boundary_is_active() {
    // The expiry condition is strict: sequence() > expiration_ledger.
    // A key expires AT sequence == expiration_ledger is still valid.
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 5;
    client.generate_view_key(&auditor, &expiration);

    // Advance to the exact expiry ledger — still valid.
    env.ledger().set_sequence_number(expiration);
    assert!(client.verify_access(&auditor));

    let pruned = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(pruned, 0, "grant at exact expiry ledger must not be pruned");

    assert!(client.verify_access(&auditor));
}

#[test]
fn test_prune_one_past_expiry_boundary_removes_grant() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 5;
    client.generate_view_key(&auditor, &expiration);

    // One ledger past expiry — now stale.
    env.ledger().set_sequence_number(expiration + 1);
    assert!(!client.verify_access(&auditor));

    let pruned = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(pruned, 1);
    assert!(client.try_get_view_key(&auditor).is_err());
}

// ---------------------------------------------------------------------------
// Idempotency: already-pruned and never-granted addresses
// ---------------------------------------------------------------------------

#[test]
fn test_prune_already_pruned_auditor_is_noop() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 5;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);

    // First prune — removes the grant.
    let first = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(first, 1);

    // Second prune of the same address — tombstone exists, AuditorKey absent.
    let second = client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    assert_eq!(second, 0, "second prune of same address must be a no-op");
}

#[test]
fn test_prune_address_with_no_grant_is_noop() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);

    // No grant was ever issued — should return 0 and not panic.
    let pruned = client
        .prune_expired_grants(&addr_vec(&env, &[stranger]))
        .unwrap();
    assert_eq!(pruned, 0);
}

#[test]
fn test_prune_mixed_batch_only_counts_expired() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let expired_auditor = soroban_sdk::Address::generate(&env);
    let active_auditor = soroban_sdk::Address::generate(&env);
    let ungranteed = soroban_sdk::Address::generate(&env);

    let seq = env.ledger().sequence();
    let short_expiry = seq + 5;
    let long_expiry = seq + 1_000;

    client.generate_view_key(&expired_auditor, &short_expiry);
    client.generate_view_key(&active_auditor, &long_expiry);

    env.ledger().set_sequence_number(short_expiry + 1);

    let pruned = client
        .prune_expired_grants(&addr_vec(
            &env,
            &[expired_auditor.clone(), active_auditor.clone(), ungranteed],
        ))
        .unwrap();

    assert_eq!(pruned, 1, "only the expired grant should be pruned");
    assert!(!client.verify_access(&expired_auditor));
    assert!(client.verify_access(&active_auditor));
}

// ---------------------------------------------------------------------------
// Audit history preservation
// ---------------------------------------------------------------------------

#[test]
fn test_audit_log_entries_preserved_after_pruning() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;
    client.generate_view_key(&auditor, &expiration);

    // Record audit log entries while the grant is active.
    let amount: i128 = 100_000;
    let blinding = BytesN::from_array(&env, &[0xAB; 32]);
    let mut preimage = soroban_sdk::Bytes::new(&env);
    preimage.extend_from_array(&amount.to_le_bytes());
    let blinding_slice: [u8; 32] = (&blinding).into();
    preimage.extend_from_array(&blinding_slice);
    let commitment: BytesN<32> = env.crypto().sha256(&preimage).into();

    client.verify_commitment_with_key(
        &auditor,
        &commitment,
        &amount,
        &blinding,
        &AuditScope::EmployeeList,
    );

    let company_id = Symbol::new(&env, "default");
    let count_before = client.get_audit_log_count(&company_id);
    assert!(count_before > 0, "audit log should have entries before pruning");

    // Expire and prune the grant.
    env.ledger().set_sequence_number(expiration + 1);
    client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();

    // Audit log entries must survive pruning — count is unchanged.
    let count_after = client.get_audit_log_count(&company_id);
    assert_eq!(
        count_after, count_before,
        "audit log entries must not be removed by pruning"
    );

    // The existing entries are still queryable.
    let result = client.query_by_company(&company_id);
    assert!(
        !result.entries.is_empty(),
        "historical audit entries must remain queryable after pruning"
    );
}

#[test]
fn test_pruned_grant_ref_tombstone_is_written() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 7;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);
    client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();

    let tombstone = client
        .get_pruned_grant_ref(&auditor)
        .expect("PrunedGrantRef tombstone must exist after pruning");

    assert_eq!(tombstone.expired_at_ledger, expiration);
    assert_eq!(tombstone.pruned_at_ledger, expiration + 1);
    // key_digest is 32 bytes of SHA-256 — just assert it is non-zero.
    let digest_bytes: [u8; 32] = tombstone.key_digest.into();
    assert_ne!(digest_bytes, [0u8; 32], "key_digest must be non-zero");
}

#[test]
fn test_get_pruned_grant_ref_returns_none_for_active_grant() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    // No pruning has happened.
    let tombstone = client.get_pruned_grant_ref(&auditor);
    assert!(tombstone.is_none(), "no tombstone for an active grant");
}

// ---------------------------------------------------------------------------
// AuditGrantPruned event emission
// ---------------------------------------------------------------------------

#[test]
fn test_prune_emits_audit_grant_pruned_event() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    let expiration = seq + 10;
    client.generate_view_key(&auditor, &expiration);

    env.ledger().set_sequence_number(expiration + 1);

    let before = env.events().all().len();
    client
        .prune_expired_grants(&addr_vec(&env, &[auditor.clone()]))
        .unwrap();
    let after = env.events().all().len();

    assert_eq!(after, before + 1, "exactly one AuditGrantPruned event emitted");

    let event = env.events().all().get(after - 1).unwrap();
    // topics: ("AuditGrantPruned", auditor)
    assert_eq!(event.1.len(), 2);
    let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(sym, Symbol::new(&env, "AuditGrantPruned"));
    let addr: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
    assert_eq!(addr, auditor);
}

#[test]
fn test_prune_no_event_for_active_grant() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = soroban_sdk::Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let before = env.events().all().len();
    client
        .prune_expired_grants(&addr_vec(&env, &[auditor]))
        .unwrap();
    let after = env.events().all().len();

    assert_eq!(after, before, "no event emitted when no grant was pruned");
}

#[test]
fn test_prune_no_event_for_never_granted_address() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let stranger = soroban_sdk::Address::generate(&env);
    let before = env.events().all().len();
    client
        .prune_expired_grants(&addr_vec(&env, &[stranger]))
        .unwrap();
    let after = env.events().all().len();

    assert_eq!(after, before, "no event emitted for address with no grant");
}

// ---------------------------------------------------------------------------
// Enumeration index (AuditorCount / get_auditor_at_index)
// ---------------------------------------------------------------------------

#[test]
fn test_registered_grant_count_increments_on_each_generate() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    assert_eq!(client.get_registered_grant_count(), 0);

    let seq = env.ledger().sequence();
    let a1 = soroban_sdk::Address::generate(&env);
    let a2 = soroban_sdk::Address::generate(&env);

    client.generate_view_key(&a1, &(seq + 100));
    assert_eq!(client.get_registered_grant_count(), 1);

    client.generate_view_key(&a2, &(seq + 200));
    assert_eq!(client.get_registered_grant_count(), 2);
}

#[test]
fn test_get_auditor_at_index_returns_correct_address() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let seq = env.ledger().sequence();
    let a1 = soroban_sdk::Address::generate(&env);
    let a2 = soroban_sdk::Address::generate(&env);

    client.generate_view_key(&a1, &(seq + 100));
    client.generate_view_key(&a2, &(seq + 200));

    let at0 = client.get_auditor_at_index(&0u32).expect("index 0 must exist");
    let at1 = client.get_auditor_at_index(&1u32).expect("index 1 must exist");

    assert_eq!(at0, a1);
    assert_eq!(at1, a2);
}

#[test]
fn test_get_auditor_at_index_out_of_bounds_returns_none() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    assert!(
        client.get_auditor_at_index(&0u32).is_none(),
        "out-of-bounds index must return None"
    );
}

// ---------------------------------------------------------------------------
// Batch-size limit
// ---------------------------------------------------------------------------

#[test]
fn test_prune_batch_too_large_returns_error() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    // Build a list of 51 addresses (one over MAX_PRUNE_BATCH = 50).
    let seq = env.ledger().sequence();
    let mut big_batch = Vec::new(&env);
    for _ in 0..51u32 {
        let addr = soroban_sdk::Address::generate(&env);
        // Grant a key so the list is realistic.
        client.generate_view_key(&addr, &(seq + 1_000));
        big_batch.push_back(addr);
    }

    let result = client.try_prune_expired_grants(&big_batch);
    assert_eq!(
        result.unwrap_err().unwrap(),
        AuditError::PruneBatchTooLarge,
        "batch of 51 must be rejected"
    );
}

#[test]
fn test_prune_batch_of_exactly_50_is_accepted() {
    let (env, contract_id) = setup();
    let client = AuditModuleClient::new(&env, &contract_id);

    let seq = env.ledger().sequence();
    let expiration = seq + 5;
    let mut batch = Vec::new(&env);
    for _ in 0..50u32 {
        let addr = soroban_sdk::Address::generate(&env);
        client.generate_view_key(&addr, &expiration);
        batch.push_back(addr);
    }

    env.ledger().set_sequence_number(expiration + 1);

    let result = client.try_prune_expired_grants(&batch);
    assert!(result.is_ok(), "batch of exactly 50 must be accepted");
    assert_eq!(result.unwrap().unwrap(), 50);
}
