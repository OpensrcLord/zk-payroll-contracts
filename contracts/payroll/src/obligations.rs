use soroban_sdk::{contracttype, Bytes, BytesN, Env};

/// An immutable snapshot of payroll obligations reviewed prior to lock, execution, cancellation, and reconciliation.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObligationSnapshot {
    pub run_id: u64,
    pub obligation_root: BytesN<32>,
    pub total_obligation_amount: i128,
    pub obligation_count: u32,
    pub created_at: u64,
}

/// Computes a deterministic cryptographic digest binding obligation snapshot fields.
///
/// Binds domain separator `b"zkpayroll_obligation_snapshot_v1"` with run_id,
/// obligation_root, total_obligation_amount, obligation_count, and created_at.
pub fn compute_obligation_snapshot_digest(env: &Env, snapshot: &ObligationSnapshot) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_slice(b"zkpayroll_obligation_snapshot_v1");
    preimage.extend_from_array(&snapshot.run_id.to_le_bytes());
    let root_slice: [u8; 32] = (&snapshot.obligation_root).into();
    preimage.extend_from_array(&root_slice);
    preimage.extend_from_array(&snapshot.total_obligation_amount.to_le_bytes());
    preimage.extend_from_array(&snapshot.obligation_count.to_le_bytes());
    preimage.extend_from_array(&snapshot.created_at.to_le_bytes());
    env.crypto().sha256(&preimage).into()
}

/// Verifies that a stored obligation snapshot matches the given parameters.
pub fn verify_snapshot_integrity(
    env: &Env,
    stored: &ObligationSnapshot,
    expected_root: &BytesN<32>,
    expected_amount: i128,
    expected_count: u32,
) -> bool {
    let zero = BytesN::from_array(env, &[0u8; 32]);
    if *expected_root == zero || expected_amount <= 0 || expected_count == 0 {
        return false;
    }
    stored.obligation_root == *expected_root
        && stored.total_obligation_amount == expected_amount
        && stored.obligation_count == expected_count
}
