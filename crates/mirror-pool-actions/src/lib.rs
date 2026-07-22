#![forbid(unsafe_code)]
//! Allowlisted participant-owned action templates and central fail-closed safety policy.

use async_trait::async_trait;
use mirror_pool_core::{Digest32, SafetyClassification};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Central runtime guard applied before simulation and sending.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SafetyPolicy {
    pub dry_run: bool,
    pub sending_enabled: bool,
    pub loopback_only: bool,
    pub simulation_required: bool,
    pub max_compute_units: u32,
    pub max_priority_fee_micro_lamports: u64,
    pub max_transaction_fee_lamports: u64,
    pub max_local_value: u64,
    pub max_concurrent_sends: u16,
    pub max_sends_per_round: u32,
    pub allowed_program_ids: Vec<[u8; 32]>,
    pub allowed_templates: Vec<String>,
    pub emergency_stop: bool,
}

impl Default for SafetyPolicy {
    fn default() -> Self {
        Self {
            dry_run: true,
            sending_enabled: false,
            loopback_only: true,
            simulation_required: true,
            max_compute_units: 200_000,
            max_priority_fee_micro_lamports: 1_000,
            max_transaction_fee_lamports: 20_000,
            max_local_value: 1_000_000,
            max_concurrent_sends: 4,
            max_sends_per_round: 50,
            allowed_program_ids: Vec::new(),
            allowed_templates: vec!["memo-v1".to_owned(), "compute-budget-shape-v1".to_owned()],
            emergency_stop: false,
        }
    }
}

impl SafetyPolicy {
    /// Validate a prepared action and RPC target before it may be simulated or sent.
    pub fn validate(
        &self,
        action: &PreparedAction,
        rpc_url: &Url,
        sending: bool,
        simulation_succeeded: bool,
        estimated_fee_lamports: u64,
        explicit_confirmation: bool,
    ) -> Result<(), ActionError> {
        if self.emergency_stop {
            return Err(ActionError::EmergencyStop);
        }
        if !self.allowed_templates.contains(&action.template_id) {
            return Err(ActionError::TemplateNotAllowed);
        }
        if action
            .program_ids
            .iter()
            .any(|program| !self.allowed_program_ids.contains(program))
        {
            return Err(ActionError::ProgramNotAllowed);
        }
        if action.compute_units > self.max_compute_units {
            return Err(ActionError::ComputeLimitExceeded);
        }
        if action.priority_fee_micro_lamports > self.max_priority_fee_micro_lamports {
            return Err(ActionError::PriorityFeeExceeded);
        }
        if action.value > self.max_local_value {
            return Err(ActionError::ValueLimitExceeded);
        }
        if action.instruction_count != 1 || action.program_ids.len() != 1 {
            return Err(ActionError::InstructionShapeInvalid);
        }
        if action.estimated_size > 1232 {
            return Err(ActionError::SizeExceeded);
        }
        if estimated_fee_lamports > self.max_transaction_fee_lamports {
            return Err(ActionError::TransactionFeeExceeded);
        }
        if self.loopback_only && !is_loopback(rpc_url) {
            return Err(ActionError::NonLoopbackRpc);
        }
        if sending {
            if self.dry_run || !self.sending_enabled {
                return Err(ActionError::SendingDisabled);
            }
            if self.simulation_required && !simulation_succeeded {
                return Err(ActionError::SimulationRequired);
            }
            if !explicit_confirmation {
                return Err(ActionError::ConfirmationRequired);
            }
            #[cfg(not(feature = "public-cluster-execution"))]
            if !is_loopback(rpc_url) {
                return Err(ActionError::PublicClusterCompileGuard);
            }
        }
        Ok(())
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    )
}

/// Sanitized participant-owned action plan. It contains no signer material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedAction {
    pub template_id: String,
    pub program_ids: Vec<[u8; 32]>,
    pub instruction_count: u8,
    pub payload: Vec<u8>,
    pub compute_units: u32,
    pub priority_fee_micro_lamports: u64,
    pub value: u64,
    pub estimated_size: u16,
    pub safety: SafetyClassification,
}

/// Participant-specific parameters accepted by built-in templates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionParameters {
    Memo { text: String },
    ComputeBudget { units: u32, priority_fee: u64 },
    LocalTokenHousekeeping { amount: u64, close_account: bool },
    LocalStakeLifecycle { lamports: u64, deactivate: bool },
}

/// Simulation result used as a mandatory send precondition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationResult {
    pub succeeded: bool,
    pub estimated_fee_lamports: u64,
    pub compute_units_consumed: u32,
    pub redacted_error: Option<String>,
}

/// Extension point for safe synchronized action shapes.
#[async_trait]
pub trait ActionTemplateDriver: Send + Sync {
    fn identifier(&self) -> &'static str;
    fn version(&self) -> u16;
    fn category(&self) -> &'static str;
    fn required_program_ids(&self) -> Vec<[u8; 32]>;
    fn safety_classification(&self) -> SafetyClassification;
    fn prepare(&self, parameters: &ActionParameters) -> Result<PreparedAction, ActionError>;
    async fn simulate(&self, action: &PreparedAction) -> Result<SimulationResult, ActionError>;
    fn redacted_fingerprint(&self, action: &PreparedAction) -> Digest32;
}

/// Safe bounded memo-shape template.
#[derive(Clone, Debug)]
pub struct MemoTemplate {
    pub memo_program_id: [u8; 32],
}

/// Bounded compute-budget shape; it cannot include arbitrary instructions.
#[derive(Clone, Debug)]
pub struct ComputeBudgetShapeTemplate {
    pub compute_budget_program_id: [u8; 32],
}

#[async_trait]
impl ActionTemplateDriver for ComputeBudgetShapeTemplate {
    fn identifier(&self) -> &'static str {
        "compute-budget-shape-v1"
    }
    fn version(&self) -> u16 {
        1
    }
    fn category(&self) -> &'static str {
        "compute_budget"
    }
    fn required_program_ids(&self) -> Vec<[u8; 32]> {
        vec![self.compute_budget_program_id]
    }
    fn safety_classification(&self) -> SafetyClassification {
        SafetyClassification::LowRisk
    }
    fn prepare(&self, parameters: &ActionParameters) -> Result<PreparedAction, ActionError> {
        let ActionParameters::ComputeBudget {
            units,
            priority_fee,
        } = parameters
        else {
            return Err(ActionError::WrongParameters);
        };
        if !(10_000..=200_000).contains(units) || *priority_fee > 1_000 {
            return Err(ActionError::ComputeLimitExceeded);
        }
        let canonical_units = units.div_ceil(25_000) * 25_000;
        let mut payload = canonical_units.to_le_bytes().to_vec();
        payload.extend_from_slice(&priority_fee.to_le_bytes());
        Ok(prepared(
            self.identifier(),
            self.required_program_ids(),
            payload,
            canonical_units,
            *priority_fee,
            0,
            SafetyClassification::LowRisk,
        ))
    }
    async fn simulate(&self, action: &PreparedAction) -> Result<SimulationResult, ActionError> {
        bounded_simulation(action)
    }
    fn redacted_fingerprint(&self, action: &PreparedAction) -> Digest32 {
        Digest32::hash(b"compute-shape", &action.payload)
    }
}

/// Localnet-only participant-owned test-token account lifecycle.
#[derive(Clone, Debug)]
pub struct LocalTokenHousekeepingTemplate {
    pub token_program_id: [u8; 32],
}
#[async_trait]
impl ActionTemplateDriver for LocalTokenHousekeepingTemplate {
    fn identifier(&self) -> &'static str {
        "local-token-housekeeping-v1"
    }
    fn version(&self) -> u16 {
        1
    }
    fn category(&self) -> &'static str {
        "local_test_token"
    }
    fn required_program_ids(&self) -> Vec<[u8; 32]> {
        vec![self.token_program_id]
    }
    fn safety_classification(&self) -> SafetyClassification {
        SafetyClassification::LocalOnly
    }
    fn prepare(&self, parameters: &ActionParameters) -> Result<PreparedAction, ActionError> {
        let ActionParameters::LocalTokenHousekeeping {
            amount,
            close_account,
        } = parameters
        else {
            return Err(ActionError::WrongParameters);
        };
        if *amount > 1_000_000 {
            return Err(ActionError::ValueLimitExceeded);
        }
        let mut payload = amount.to_le_bytes().to_vec();
        payload.push(u8::from(*close_account));
        Ok(prepared(
            self.identifier(),
            self.required_program_ids(),
            payload,
            50_000,
            0,
            *amount,
            SafetyClassification::LocalOnly,
        ))
    }
    async fn simulate(&self, action: &PreparedAction) -> Result<SimulationResult, ActionError> {
        bounded_simulation(action)
    }
    fn redacted_fingerprint(&self, action: &PreparedAction) -> Digest32 {
        Digest32::hash(
            b"token-housekeeping-shape",
            &[action.payload.last().copied().unwrap_or(0)],
        )
    }
}

/// Localnet-only participant-owned native stake create/deactivate shape.
#[derive(Clone, Debug)]
pub struct LocalStakeLifecycleTemplate {
    pub stake_program_id: [u8; 32],
}
#[async_trait]
impl ActionTemplateDriver for LocalStakeLifecycleTemplate {
    fn identifier(&self) -> &'static str {
        "local-stake-lifecycle-v1"
    }
    fn version(&self) -> u16 {
        1
    }
    fn category(&self) -> &'static str {
        "local_native_stake"
    }
    fn required_program_ids(&self) -> Vec<[u8; 32]> {
        vec![self.stake_program_id]
    }
    fn safety_classification(&self) -> SafetyClassification {
        SafetyClassification::LocalOnly
    }
    fn prepare(&self, parameters: &ActionParameters) -> Result<PreparedAction, ActionError> {
        let ActionParameters::LocalStakeLifecycle {
            lamports,
            deactivate,
        } = parameters
        else {
            return Err(ActionError::WrongParameters);
        };
        if *lamports == 0 || *lamports > 1_000_000 {
            return Err(ActionError::ValueLimitExceeded);
        }
        let mut payload = lamports.to_le_bytes().to_vec();
        payload.push(u8::from(*deactivate));
        Ok(prepared(
            self.identifier(),
            self.required_program_ids(),
            payload,
            100_000,
            0,
            *lamports,
            SafetyClassification::LocalOnly,
        ))
    }
    async fn simulate(&self, action: &PreparedAction) -> Result<SimulationResult, ActionError> {
        bounded_simulation(action)
    }
    fn redacted_fingerprint(&self, action: &PreparedAction) -> Digest32 {
        Digest32::hash(
            b"stake-lifecycle-shape",
            &[action.payload.last().copied().unwrap_or(0)],
        )
    }
}

fn prepared(
    template: &str,
    program_ids: Vec<[u8; 32]>,
    payload: Vec<u8>,
    compute_units: u32,
    priority_fee: u64,
    value: u64,
    safety: SafetyClassification,
) -> PreparedAction {
    PreparedAction {
        template_id: template.to_owned(),
        program_ids,
        instruction_count: 1,
        estimated_size: u16::try_from(100_usize.saturating_add(payload.len())).unwrap_or(u16::MAX),
        payload,
        compute_units,
        priority_fee_micro_lamports: priority_fee,
        value,
        safety,
    }
}
fn bounded_simulation(action: &PreparedAction) -> Result<SimulationResult, ActionError> {
    if action.estimated_size > 1232 {
        return Err(ActionError::SizeExceeded);
    }
    Ok(SimulationResult {
        succeeded: true,
        estimated_fee_lamports: 5_000,
        compute_units_consumed: action.compute_units / 2,
        redacted_error: None,
    })
}

#[async_trait]
impl ActionTemplateDriver for MemoTemplate {
    fn identifier(&self) -> &'static str {
        "memo-v1"
    }
    fn version(&self) -> u16 {
        1
    }
    fn category(&self) -> &'static str {
        "memo"
    }
    fn required_program_ids(&self) -> Vec<[u8; 32]> {
        vec![self.memo_program_id]
    }
    fn safety_classification(&self) -> SafetyClassification {
        SafetyClassification::LowRisk
    }

    fn prepare(&self, parameters: &ActionParameters) -> Result<PreparedAction, ActionError> {
        let ActionParameters::Memo { text } = parameters else {
            return Err(ActionError::WrongParameters);
        };
        if text.is_empty() || text.len() > 64 || text.chars().any(char::is_control) {
            return Err(ActionError::InvalidMemo);
        }
        let bucket = if text.len() <= 16 {
            16
        } else if text.len() <= 32 {
            32
        } else {
            64
        };
        let mut payload = text.as_bytes().to_vec();
        payload.resize(bucket, b' ');
        Ok(PreparedAction {
            template_id: self.identifier().to_owned(),
            program_ids: self.required_program_ids(),
            instruction_count: 1,
            payload,
            compute_units: 10_000,
            priority_fee_micro_lamports: 0,
            value: 0,
            estimated_size: u16::try_from(100 + bucket).map_err(|_| ActionError::SizeExceeded)?,
            safety: self.safety_classification(),
        })
    }

    async fn simulate(&self, action: &PreparedAction) -> Result<SimulationResult, ActionError> {
        Ok(SimulationResult {
            succeeded: action.estimated_size <= 1232,
            estimated_fee_lamports: 5_000,
            compute_units_consumed: 4_000,
            redacted_error: None,
        })
    }

    fn redacted_fingerprint(&self, action: &PreparedAction) -> Digest32 {
        Digest32::hash(
            b"memo-shape",
            &[u8::try_from(action.payload.len()).unwrap_or(u8::MAX)],
        )
    }
}

/// Built-in template catalogue. Local token/stake variants are represented but remain local-only.
pub fn built_in_template_names() -> [&'static str; 4] {
    [
        "memo-v1",
        "compute-budget-shape-v1",
        "local-token-housekeeping-v1",
        "local-stake-lifecycle-v1",
    ]
}

/// Action policy failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ActionError {
    #[error("emergency stop is active")]
    EmergencyStop,
    #[error("action template is not allowed")]
    TemplateNotAllowed,
    #[error("program id is not allowlisted")]
    ProgramNotAllowed,
    #[error("compute-unit limit exceeded")]
    ComputeLimitExceeded,
    #[error("priority-fee limit exceeded")]
    PriorityFeeExceeded,
    #[error("transaction-fee limit exceeded")]
    TransactionFeeExceeded,
    #[error("action value limit exceeded")]
    ValueLimitExceeded,
    #[error("RPC target is not loopback")]
    NonLoopbackRpc,
    #[error("transaction sending is disabled")]
    SendingDisabled,
    #[error("successful simulation is required")]
    SimulationRequired,
    #[error("explicit confirmation is required")]
    ConfirmationRequired,
    #[error("public-cluster execution feature is disabled")]
    PublicClusterCompileGuard,
    #[error("parameters do not match template")]
    WrongParameters,
    #[error("memo violates bounded content policy")]
    InvalidMemo,
    #[error("transaction size exceeded")]
    SizeExceeded,
    #[error("instruction shape is invalid")]
    InstructionShapeInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fail_closed() {
        let policy = SafetyPolicy::default();
        assert!(policy.dry_run);
        assert!(!policy.sending_enabled);
        assert!(policy.loopback_only);
        assert!(policy.simulation_required);
    }

    #[test]
    fn memo_has_canonical_bucket() {
        let template = MemoTemplate {
            memo_program_id: [7; 32],
        };
        let action = template
            .prepare(&ActionParameters::Memo {
                text: "hello".to_owned(),
            })
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(action.payload.len(), 16);
        assert_eq!(action.instruction_count, 1);
    }

    #[test]
    fn public_rpc_is_rejected_by_default() {
        let template = MemoTemplate {
            memo_program_id: [7; 32],
        };
        let action = template
            .prepare(&ActionParameters::Memo {
                text: "hello".to_owned(),
            })
            .unwrap_or_else(|error| panic!("{error}"));
        let policy = SafetyPolicy {
            allowed_program_ids: vec![[7; 32]],
            ..SafetyPolicy::default()
        };
        let url = Url::parse("https://api.mainnet-beta.solana.com")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            policy.validate(&action, &url, false, false, 0, false),
            Err(ActionError::NonLoopbackRpc)
        );
    }

    #[test]
    fn tampered_shape_and_excessive_fee_are_rejected() {
        let template = MemoTemplate {
            memo_program_id: [7; 32],
        };
        let mut action = template
            .prepare(&ActionParameters::Memo {
                text: "hello".to_owned(),
            })
            .unwrap_or_else(|error| panic!("{error}"));
        let policy = SafetyPolicy {
            allowed_program_ids: vec![[7; 32]],
            ..SafetyPolicy::default()
        };
        let url = Url::parse("http://127.0.0.1:8899").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            policy.validate(&action, &url, false, true, 20_001, false),
            Err(ActionError::TransactionFeeExceeded)
        );
        action.instruction_count = 2;
        assert_eq!(
            policy.validate(&action, &url, false, true, 5_000, false),
            Err(ActionError::InstructionShapeInvalid)
        );
    }

    #[tokio::test]
    async fn every_builtin_template_prepares_and_simulates() {
        let templates: Vec<(Box<dyn ActionTemplateDriver>, ActionParameters)> = vec![
            (
                Box::new(ComputeBudgetShapeTemplate {
                    compute_budget_program_id: [1; 32],
                }),
                ActionParameters::ComputeBudget {
                    units: 51_000,
                    priority_fee: 10,
                },
            ),
            (
                Box::new(LocalTokenHousekeepingTemplate {
                    token_program_id: [2; 32],
                }),
                ActionParameters::LocalTokenHousekeeping {
                    amount: 10,
                    close_account: true,
                },
            ),
            (
                Box::new(LocalStakeLifecycleTemplate {
                    stake_program_id: [3; 32],
                }),
                ActionParameters::LocalStakeLifecycle {
                    lamports: 10,
                    deactivate: false,
                },
            ),
        ];
        for (template, parameters) in templates {
            let action = template
                .prepare(&parameters)
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(
                template
                    .simulate(&action)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"))
                    .succeeded
            );
        }
    }
}
