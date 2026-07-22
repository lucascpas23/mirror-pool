#![forbid(unsafe_code)]
//! Deterministic virtual-time synchronization and adversarial privacy evaluation.

use std::collections::BTreeMap;

use mirror_pool_core::{Digest32, PrivacyBackend};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Release scheduling strategies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStrategy {
    FixedSlot,
    NarrowWindow,
    RandomizedWithinWindow,
    LatencyAware,
}

/// Feature groups available to the declared synthetic observer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObserverFeatures {
    pub timing: bool,
    pub instruction_shape: bool,
    pub fee_behavior: bool,
    pub funding_graph: bool,
    pub amount_bucket: bool,
    pub historical_behavior: bool,
}

impl Default for ObserverFeatures {
    fn default() -> Self {
        Self {
            timing: true,
            instruction_shape: true,
            fee_behavior: true,
            funding_graph: true,
            amount_bucket: true,
            historical_behavior: true,
        }
    }
}

/// Reproducible scenario configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    pub scenario_version: u16,
    pub seed: u64,
    pub participant_count: u32,
    pub backend: PrivacyBackend,
    pub release_strategy: ReleaseStrategy,
    pub execution_window_slots: u64,
    pub dropout_rate: f64,
    pub longitudinal_periods: u16,
    pub observer_features: ObserverFeatures,
}

/// One synthetic public observation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub participant: u32,
    pub executed: bool,
    pub slot: u64,
    pub fingerprint: String,
    pub score: f64,
    pub true_link: bool,
}

/// Required privacy and synchronization metrics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    pub announced_cohort_size: u32,
    pub observed_cohort_size: u32,
    pub completion_rate: f64,
    pub execution_spread_slots: u64,
    pub median_timing_deviation: f64,
    pub p95_timing_deviation: f64,
    pub unique_fingerprint_rate: f64,
    pub minimum_k_anonymity: u32,
    pub shannon_entropy: f64,
    pub effective_anonymity_set: f64,
    pub normalized_entropy: f64,
    pub linkage_precision: f64,
    pub linkage_recall: f64,
    pub linkage_f1: f64,
    pub roc_auc: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

/// Complete deterministic report row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub scenario: Scenario,
    pub metrics: EvaluationMetrics,
    pub trace_hash: Digest32,
    pub limitations: Vec<String>,
}

/// Run a deterministic synthetic experiment.
pub fn evaluate(scenario: Scenario) -> Result<EvaluationReport, EvaluationError> {
    validate(&scenario)?;
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.seed);
    let target_slot = 10_000_u64;
    let mut observations = Vec::with_capacity(scenario.participant_count as usize);
    for participant in 0..scenario.participant_count {
        let executed = !rng.gen_bool(scenario.dropout_rate);
        let slot = match scenario.release_strategy {
            ReleaseStrategy::FixedSlot => target_slot,
            ReleaseStrategy::NarrowWindow => {
                target_slot + rng.gen_range(0..=scenario.execution_window_slots.min(3))
            }
            ReleaseStrategy::RandomizedWithinWindow => {
                target_slot + rng.gen_range(0..=scenario.execution_window_slots)
            }
            ReleaseStrategy::LatencyAware => {
                target_slot + rng.gen_range(0..=scenario.execution_window_slots.min(2))
            }
        };
        let timing = if scenario.observer_features.timing {
            slot % 4
        } else {
            0
        };
        let shape = if scenario.observer_features.instruction_shape {
            participant as u64 % 5
        } else {
            0
        };
        let fee = if scenario.observer_features.fee_behavior {
            participant as u64 % 3
        } else {
            0
        };
        let funding = if scenario.observer_features.funding_graph {
            participant as u64 % 7
        } else {
            0
        };
        let amount = if scenario.observer_features.amount_bucket {
            participant as u64 % 4
        } else {
            0
        };
        let history = if scenario.observer_features.historical_behavior {
            participant as u64 % u64::from(scenario.longitudinal_periods.max(1))
        } else {
            0
        };
        let fingerprint = format!("{timing}:{shape}:{fee}:{funding}:{amount}:{history}");
        let true_link = participant % 2 == 0;
        let signal = f64::from(
            timing as u32
                + shape as u32
                + fee as u32
                + funding as u32
                + amount as u32
                + history as u32,
        );
        let score = (signal / 28.0 + rng.gen_range(0.0..0.15)).clamp(0.0, 1.0);
        observations.push(Observation {
            participant,
            executed,
            slot,
            fingerprint,
            score,
            true_link,
        });
    }
    let metrics = metrics(&observations, scenario.participant_count, target_slot);
    let trace = serde_json::to_vec(&observations).map_err(|_| EvaluationError::Serialization)?;
    Ok(EvaluationReport {
        scenario,
        metrics,
        trace_hash: Digest32::hash(b"evaluation-trace", &trace),
        limitations: vec![
            "Synthetic observations do not prove real-world anonymity or unlinkability.".to_owned(),
            "The coordinator sees submitted tickets; network and funding metadata may relink users.".to_owned(),
            "Synchronization can create a detectable cohort fingerprint.".to_owned(),
        ],
    })
}

fn validate(s: &Scenario) -> Result<(), EvaluationError> {
    if s.scenario_version != 1
        || s.participant_count < 2
        || s.participant_count > 100_000
        || s.execution_window_slots == 0
        || !(0.0..1.0).contains(&s.dropout_rate)
    {
        return Err(EvaluationError::InvalidScenario);
    }
    Ok(())
}

fn metrics(obs: &[Observation], announced: u32, target: u64) -> EvaluationMetrics {
    let executed: Vec<&Observation> = obs.iter().filter(|o| o.executed).collect();
    let observed = u32::try_from(executed.len()).unwrap_or(u32::MAX);
    let mut deviations: Vec<u64> = executed.iter().map(|o| o.slot.abs_diff(target)).collect();
    deviations.sort_unstable();
    let percentile = |fraction: f64| -> f64 {
        if deviations.is_empty() {
            return 0.0;
        }
        let index = ((deviations.len() - 1) as f64 * fraction).round() as usize;
        deviations[index] as f64
    };
    let spread = executed
        .iter()
        .map(|o| o.slot)
        .max()
        .unwrap_or(target)
        .saturating_sub(executed.iter().map(|o| o.slot).min().unwrap_or(target));
    let mut groups = BTreeMap::<&str, u32>::new();
    for o in &executed {
        *groups.entry(&o.fingerprint).or_default() += 1;
    }
    let entropy = groups.values().fold(0.0, |sum, count| {
        let p = f64::from(*count) / f64::from(observed.max(1));
        sum - p * p.ln()
    });
    let unique = groups.values().filter(|&&n| n == 1).count() as f64;
    let (tp, fp, tn, fn_) = confusion(&executed, 0.5);
    let precision = ratio(tp, tp + fp);
    let recall = ratio(tp, tp + fn_);
    EvaluationMetrics {
        announced_cohort_size: announced,
        observed_cohort_size: observed,
        completion_rate: ratio(f64::from(observed), f64::from(announced)),
        execution_spread_slots: spread,
        median_timing_deviation: percentile(0.5),
        p95_timing_deviation: percentile(0.95),
        unique_fingerprint_rate: ratio(unique, f64::from(observed)),
        minimum_k_anonymity: groups.values().copied().min().unwrap_or(0),
        shannon_entropy: entropy,
        effective_anonymity_set: entropy.exp(),
        normalized_entropy: if observed > 1 {
            entropy / f64::from(observed).ln()
        } else {
            0.0
        },
        linkage_precision: precision,
        linkage_recall: recall,
        linkage_f1: if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        },
        roc_auc: auc(&executed),
        false_positive_rate: ratio(fp, fp + tn),
        false_negative_rate: ratio(fn_, fn_ + tp),
    }
}

fn confusion(obs: &[&Observation], threshold: f64) -> (f64, f64, f64, f64) {
    obs.iter()
        .fold((0.0, 0.0, 0.0, 0.0), |(tp, fp, tn, fn_), o| {
            match (o.score >= threshold, o.true_link) {
                (true, true) => (tp + 1.0, fp, tn, fn_),
                (true, false) => (tp, fp + 1.0, tn, fn_),
                (false, false) => (tp, fp, tn + 1.0, fn_),
                (false, true) => (tp, fp, tn, fn_ + 1.0),
            }
        })
}

fn auc(obs: &[&Observation]) -> f64 {
    let positives: Vec<_> = obs.iter().filter(|o| o.true_link).collect();
    let negatives: Vec<_> = obs.iter().filter(|o| !o.true_link).collect();
    if positives.is_empty() || negatives.is_empty() {
        return 0.5;
    }
    let wins: f64 = positives
        .iter()
        .flat_map(|p| {
            negatives.iter().map(move |n| {
                if p.score > n.score {
                    1.0
                } else if (p.score - n.score).abs() < f64::EPSILON {
                    0.5
                } else {
                    0.0
                }
            })
        })
        .sum();
    wins / (positives.len() * negatives.len()) as f64
}

fn ratio(a: f64, b: f64) -> f64 {
    if b > 0.0 { a / b } else { 0.0 }
}

/// Invalid or unserializable evaluation.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum EvaluationError {
    #[error("invalid evaluation scenario")]
    InvalidScenario,
    #[error("trace serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(count: u32, dropout: f64) -> Scenario {
        Scenario {
            scenario_version: 1,
            seed: 42,
            participant_count: count,
            backend: PrivacyBackend::MerkleCohort,
            release_strategy: ReleaseStrategy::NarrowWindow,
            execution_window_slots: 4,
            dropout_rate: dropout,
            longitudinal_periods: 1,
            observer_features: ObserverFeatures::default(),
        }
    }

    #[test]
    fn results_and_trace_hash_are_deterministic() {
        let a = evaluate(scenario(100, 0.1)).unwrap_or_else(|error| panic!("{error}"));
        let b = evaluate(scenario(100, 0.1)).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(a.trace_hash, b.trace_hash);
        assert_eq!(
            a.metrics.observed_cohort_size,
            b.metrics.observed_cohort_size
        );
    }

    #[test]
    fn high_dropout_reduces_observed_set() {
        let low = evaluate(scenario(1_000, 0.05)).unwrap_or_else(|error| panic!("{error}"));
        let high = evaluate(scenario(1_000, 0.5)).unwrap_or_else(|error| panic!("{error}"));
        assert!(high.metrics.observed_cohort_size < low.metrics.observed_cohort_size);
        for value in [
            high.metrics.shannon_entropy,
            high.metrics.roc_auc,
            high.metrics.normalized_entropy,
        ] {
            assert!(value.is_finite());
        }
    }
}
