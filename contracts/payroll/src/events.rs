/// Privacy-safe event helpers for the overpayment review subsystem.
///
/// # Privacy design
///
/// Overpayment reviews must not expose salary values or per-employee payment
/// details on-chain.  Every event defined here carries only the minimum
/// identifiers needed for off-chain indexers and auditors to correlate events
/// with their own permissioned records:
///
///   * `run_id`   — the opaque u64 payroll-run identifier.
///   * `review_id` — the opaque u64 review identifier.
///   * `flagged_at` / `resolved_at` — on-chain ledger timestamps.
///   * `resolver`  — the authorized address that closed the review.
///
/// **Deliberately omitted:** amounts, employee addresses, commitment hashes,
/// proof data, and any field that would allow a passive observer to reconstruct
/// salary information.
///
/// # Event catalogue
///
/// | Symbol constant          | Topics payload                    | Data payload                          |
/// |--------------------------|-----------------------------------|---------------------------------------|
/// | `REVIEW_OPENED`          | `("payroll", "review_opened")`    | `(review_id, run_id, flagged_at)`     |
/// | `REVIEW_RESOLVED`        | `("payroll", "review_resolved")`  | `(review_id, run_id, resolved_at)`    |
/// | `ARCHIVAL_BLOCKED`       | `("payroll", "archival_blocked")` | `(run_id, review_id)`                 |

// ── Symbol string constants ───────────────────────────────────────────────────
//
// Soroban symbols are ≤ 32 characters.  These are defined as `&str` so callers
// can pass them directly to `Symbol::new(&env, REVIEW_OPENED)` without import
// boilerplate.

/// Topics name for the "review opened" event.
pub const REVIEW_OPENED: &str = "review_opened";

/// Topics name for the "review resolved" event.
pub const REVIEW_RESOLVED: &str = "review_resolved";

/// Topics name for the "archival blocked" guard event.
pub const ARCHIVAL_BLOCKED: &str = "archival_blocked";

/// Top-level contract namespace used in all event topics.
pub const PAYROLL_NS: &str = "payroll";
