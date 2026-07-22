#![forbid(unsafe_code)]
//! Bounded HTTP coordinator. The operator sees tickets and is not an anonymity service.

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mirror_pool_core::Digest32;
use mirror_pool_crypto::{JoinTicket, TicketBinding};
use mirror_pool_merkle::CohortProof;
use mirror_pool_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::Mutex};

/// Immutable coordinator policy for one active round.
#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    pub binding: TicketBinding,
    pub listen: SocketAddr,
    pub minimum_participants: u32,
    pub maximum_participants: u32,
    pub requests_per_minute: u32,
    pub max_body_bytes: usize,
}

/// Swappable coordinator interface for future federation or threshold root signing.
#[async_trait]
pub trait CoordinatorBackend: Send + Sync {
    async fn submit_ticket(
        &self,
        ticket: JoinTicket,
        current_slot: u64,
    ) -> Result<Digest32, CoordinatorError>;
    async fn seal(&self) -> Result<(Digest32, u32), CoordinatorError>;
    async fn proof(&self, commitment: Digest32) -> Result<Option<CohortProof>, CoordinatorError>;
}

/// Trusted slot source used for ticket expiry checks.
#[async_trait]
pub trait SlotSource: Send + Sync {
    async fn current_slot(&self) -> Result<u64, CoordinatorError>;
}

/// Confirmed-commitment Solana RPC slot source.
#[derive(Clone, Debug)]
pub struct RpcSlotSource {
    rpc_url: String,
}

impl RpcSlotSource {
    #[must_use]
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
        }
    }
}

#[async_trait]
impl SlotSource for RpcSlotSource {
    async fn current_slot(&self) -> Result<u64, CoordinatorError> {
        let rpc_url = self.rpc_url.clone();
        tokio::task::spawn_blocking(move || {
            RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed())
                .get_slot()
                .map_err(|_| CoordinatorError::RpcClock)
        })
        .await
        .map_err(|_| CoordinatorError::RpcClock)?
    }
}

/// SQLite-backed coordinator state.
pub struct Coordinator {
    config: CoordinatorConfig,
    store: Mutex<Store>,
    rate: Mutex<RateState>,
}
struct RateState {
    window_started: Instant,
    accepted: u32,
}

impl Coordinator {
    /// Construct with an already migrated durable store.
    #[must_use]
    pub fn new(config: CoordinatorConfig, store: Store) -> Self {
        Self {
            config,
            store: Mutex::new(store),
            rate: Mutex::new(RateState {
                window_started: Instant::now(),
                accepted: 0,
            }),
        }
    }
    async fn check_rate(&self) -> Result<(), CoordinatorError> {
        let mut rate = self.rate.lock().await;
        if rate.window_started.elapsed() >= Duration::from_secs(60) {
            rate.window_started = Instant::now();
            rate.accepted = 0;
        }
        if rate.accepted >= self.config.requests_per_minute {
            return Err(CoordinatorError::RateLimited);
        }
        rate.accepted = rate.accepted.saturating_add(1);
        Ok(())
    }
}

#[async_trait]
impl CoordinatorBackend for Coordinator {
    async fn submit_ticket(
        &self,
        ticket: JoinTicket,
        current_slot: u64,
    ) -> Result<Digest32, CoordinatorError> {
        self.check_rate().await?;
        ticket
            .verify(current_slot, &self.config.binding)
            .map_err(|_| CoordinatorError::InvalidTicket)?;
        let mut store = self.store.lock().await;
        let count =
            store.ticket_count(self.config.binding.pool_id, self.config.binding.round_id)?;
        if count >= self.config.maximum_participants {
            return Err(CoordinatorError::CohortFull);
        }
        store.accept_ticket(&ticket).map_err(CoordinatorError::from)
    }
    async fn seal(&self) -> Result<(Digest32, u32), CoordinatorError> {
        self.store
            .lock()
            .await
            .seal_cohort(
                self.config.binding.pool_id,
                self.config.binding.round_id,
                self.config.minimum_participants,
            )
            .map_err(CoordinatorError::from)
    }
    async fn proof(&self, commitment: Digest32) -> Result<Option<CohortProof>, CoordinatorError> {
        self.store
            .lock()
            .await
            .proof(
                self.config.binding.pool_id,
                self.config.binding.round_id,
                commitment,
            )
            .map_err(CoordinatorError::from)
    }
}

/// Shared HTTP service state.
#[derive(Clone)]
pub struct AppState {
    coordinator: Arc<Coordinator>,
    slot_source: Arc<dyn SlotSource>,
}
/// Accepted ticket response.
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketAccepted {
    pub commitment: Digest32,
}
/// Ticket request. Expiry is evaluated against the coordinator's trusted RPC clock.
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketSubmission {
    pub ticket: JoinTicket,
}

/// Create a request-size and timeout-bounded router.
pub fn router(coordinator: Arc<Coordinator>, slot_source: Arc<dyn SlotSource>) -> Router {
    let max_body = coordinator.config.max_body_bytes;
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({"status":"ok","privacy":"coordination-not-anonymity"}))
            }),
        )
        .route("/v1/tickets", post(submit))
        .route("/v1/cohort/seal", post(seal))
        .route("/v1/proofs/{commitment}", get(proof))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(10),
        ))
        .with_state(AppState {
            coordinator,
            slot_source,
        })
}

/// Run until SIGINT or SIGTERM.
pub async fn serve(
    coordinator: Arc<Coordinator>,
    slot_source: Arc<dyn SlotSource>,
) -> Result<(), CoordinatorError> {
    let listener = TcpListener::bind(coordinator.config.listen).await?;
    tracing::info!(listen = %coordinator.config.listen, "coordinator listening");
    axum::serve(listener, router(coordinator, slot_source))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut stream) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            stream.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}
async fn submit(
    State(state): State<AppState>,
    Json(request): Json<TicketSubmission>,
) -> Result<Json<TicketAccepted>, CoordinatorError> {
    let current_slot = state.slot_source.current_slot().await?;
    let commitment = state
        .coordinator
        .submit_ticket(request.ticket, current_slot)
        .await?;
    Ok(Json(TicketAccepted { commitment }))
}
async fn seal(
    State(state): State<AppState>,
) -> Result<Json<BTreeMap<&'static str, String>>, CoordinatorError> {
    let (root, count) = state.coordinator.seal().await?;
    Ok(Json(BTreeMap::from([
        ("root", root.to_hex()),
        ("count", count.to_string()),
    ])))
}
async fn proof(
    State(state): State<AppState>,
    Path(hex_value): Path<String>,
) -> Result<Json<CohortProof>, CoordinatorError> {
    let bytes = hex::decode(hex_value).map_err(|_| CoordinatorError::InvalidCommitment)?;
    let commitment = Digest32(
        bytes
            .try_into()
            .map_err(|_| CoordinatorError::InvalidCommitment)?,
    );
    state
        .coordinator
        .proof(commitment)
        .await?
        .map(Json)
        .ok_or(CoordinatorError::ProofNotFound)
}

/// Non-sensitive coordinator failures.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("invalid ticket")]
    InvalidTicket,
    #[error("invalid commitment")]
    InvalidCommitment,
    #[error("submission rate exceeded")]
    RateLimited,
    #[error("cohort is full")]
    CohortFull,
    #[error("proof not found")]
    ProofNotFound,
    #[error("trusted RPC slot is unavailable")]
    RpcClock,
    #[error("store failure: {0}")]
    Store(#[from] StoreError),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
}
impl IntoResponse for CoordinatorError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidTicket | Self::InvalidCommitment => StatusCode::BAD_REQUEST,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::CohortFull => StatusCode::CONFLICT,
            Self::ProofNotFound => StatusCode::NOT_FOUND,
            Self::Store(StoreError::DuplicateTicket | StoreError::ConflictingSchedule) => {
                StatusCode::CONFLICT
            }
            Self::RpcClock => StatusCode::SERVICE_UNAVAILABLE,
            Self::Store(_) | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(serde_json::json!({"error": self.to_string()}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use ed25519_dalek::SigningKey;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use tower::ServiceExt;

    struct FixedSlot(u64);

    #[async_trait]
    impl SlotSource for FixedSlot {
        async fn current_slot(&self) -> Result<u64, CoordinatorError> {
            Ok(self.0)
        }
    }

    struct UnavailableSlot;

    #[async_trait]
    impl SlotSource for UnavailableSlot {
        async fn current_slot(&self) -> Result<u64, CoordinatorError> {
            Err(CoordinatorError::RpcClock)
        }
    }

    fn config(limit: u32) -> CoordinatorConfig {
        CoordinatorConfig {
            binding: TicketBinding {
                pool_id: Digest32([1; 32]),
                round_id: 7,
                action_template_hash: Digest32([2; 32]),
            },
            listen: "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
            minimum_participants: 2,
            maximum_participants: 4,
            requests_per_minute: limit,
            max_body_bytes: 16 * 1024,
        }
    }

    fn ticket(index: u8) -> JoinTicket {
        let mut rng = ChaCha20Rng::from_seed([index; 32]);
        JoinTicket::create(
            &mut rng,
            &SigningKey::from_bytes(&[index.saturating_add(10); 32]),
            Digest32([1; 32]),
            7,
            Digest32([2; 32]),
            100,
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .0
    }

    #[tokio::test]
    async fn accepts_seals_and_returns_verified_proofs() {
        let coordinator = Coordinator::new(
            config(10),
            Store::memory().unwrap_or_else(|error| panic!("{error}")),
        );
        let first = ticket(1);
        let second = ticket(2);
        let commitment = coordinator
            .submit_ticket(first, 1)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(coordinator.submit_ticket(second, 1).await.is_ok());
        let (root, count) = coordinator
            .seal()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(count, 2);
        let proof = coordinator
            .proof(commitment)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("proof missing"));
        assert_eq!(proof.verify(root, 7), Ok(()));
    }

    #[tokio::test]
    async fn rate_limit_and_duplicate_constraints_fail_closed() {
        let coordinator = Coordinator::new(
            config(10),
            Store::memory().unwrap_or_else(|error| panic!("{error}")),
        );
        let value = ticket(3);
        assert!(coordinator.submit_ticket(value.clone(), 1).await.is_ok());
        assert!(matches!(
            coordinator.submit_ticket(value, 1).await,
            Err(CoordinatorError::Store(StoreError::DuplicateTicket))
        ));
        let limited = Coordinator::new(
            config(1),
            Store::memory().unwrap_or_else(|error| panic!("{error}")),
        );
        assert!(limited.submit_ticket(ticket(4), 1).await.is_ok());
        assert!(matches!(
            limited.submit_ticket(ticket(5), 1).await,
            Err(CoordinatorError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn http_uses_trusted_slot_and_rejects_expired_ticket() {
        let service = router(
            Arc::new(Coordinator::new(
                config(10),
                Store::memory().unwrap_or_else(|error| panic!("{error}")),
            )),
            Arc::new(FixedSlot(101)),
        );
        let body = serde_json::to_vec(&TicketSubmission { ticket: ticket(6) })
            .unwrap_or_else(|error| panic!("{error}"));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tickets")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn http_fails_closed_when_trusted_slot_is_unavailable() {
        let service = router(
            Arc::new(Coordinator::new(
                config(10),
                Store::memory().unwrap_or_else(|error| panic!("{error}")),
            )),
            Arc::new(UnavailableSlot),
        );
        let body = serde_json::to_vec(&TicketSubmission { ticket: ticket(7) })
            .unwrap_or_else(|error| panic!("{error}"));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tickets")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
