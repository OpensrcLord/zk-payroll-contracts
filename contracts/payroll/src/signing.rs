use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

/// Multi-stage approval state for a payroll draft/batch.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiStageApproval {
    pub draft_id: u64,
    pub protected_content_hash: BytesN<32>,
    pub required_approvals: u32,
    pub current_approvals: u32,
    pub current_stage: u32,
    pub is_locked: bool,
    pub signers: Vec<Address>,
}

/// Compute a protected content hash covering fields that require re-approval if changed.
pub fn compute_protected_content_hash(
    env: &Env,
    total_amount: i128,
    employee_count: u32,
    obligation_root: &BytesN<32>,
    metadata_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_slice(b"zkpayroll_protected_content_v1");
    preimage.extend_from_array(&total_amount.to_le_bytes());
    preimage.extend_from_array(&employee_count.to_le_bytes());
    let ob_slice: [u8; 32] = obligation_root.into();
    preimage.extend_from_array(&ob_slice);
    let meta_slice: [u8; 32] = metadata_hash.into();
    preimage.extend_from_array(&meta_slice);
    env.crypto().sha256(&preimage).into()
}

/// Create a fresh multi-stage approval tracker for a draft.
pub fn init_multi_stage_approval(
    env: &Env,
    draft_id: u64,
    protected_content_hash: BytesN<32>,
    required_approvals: u32,
) -> MultiStageApproval {
    MultiStageApproval {
        draft_id,
        protected_content_hash,
        required_approvals,
        current_approvals: 0,
        current_stage: 0,
        is_locked: false,
        signers: Vec::new(env),
    }
}
