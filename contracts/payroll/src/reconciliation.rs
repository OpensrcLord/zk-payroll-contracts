use soroban_sdk::{contracttype, Address, Env};

/// Lifecycle stage for treasury reservation reconciliation checkpoints.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CheckpointStage {
    Lock = 1,
    Execution = 2,
    Cancellation = 3,
    Expiry = 4,
    Close = 5,
}

/// Record of a treasury reservation reconciliation check.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationCheckpoint {
    pub run_id: u64,
    pub stage: CheckpointStage,
    pub expected_reserved_amount: i128,
    pub actual_reserved_amount: i128,
    pub asset: Address,
    pub is_reconciled: bool,
    pub timestamp: u64,
}

/// Create a new reservation checkpoint record.
pub fn create_checkpoint(
    env: &Env,
    run_id: u64,
    stage: CheckpointStage,
    expected_reserved_amount: i128,
    actual_reserved_amount: i128,
    asset: Address,
) -> ReservationCheckpoint {
    let is_reconciled = expected_reserved_amount == actual_reserved_amount;
    ReservationCheckpoint {
        run_id,
        stage,
        expected_reserved_amount,
        actual_reserved_amount,
        asset,
        is_reconciled,
        timestamp: env.ledger().timestamp(),
    }
}
