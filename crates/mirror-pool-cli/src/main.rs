#![forbid(unsafe_code)]
use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use mirror_pool_coordinator::{Coordinator, CoordinatorConfig};
use mirror_pool_core::{
    Cluster, CompletionPolicy, Digest32, GovernancePolicy, PoolConfig, PrivacyBackend, Round,
    RoundState, SCHEMA_VERSION,
};
use mirror_pool_crypto::{JoinTicket, TicketBinding};
use mirror_pool_merkle::CohortProof;
use mirror_pool_simulator::{
    EvaluationReport, ObserverFeatures, ReleaseStrategy, Scenario, evaluate,
};
use mirror_pool_store::Store;
use rand::RngCore as _;
use std::{collections::BTreeSet, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use url::Url;

#[derive(Parser)]
#[command(
    name = "mirror-pool",
    version,
    about = "Non-custodial behavioral coordination",
    long_about = "Coordinates compatible participant-owned Solana actions. Never mixes or custodies funds and does not provide cryptographic anonymity."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(default_value = ".mirror-pool")]
        directory: PathBuf,
    },
    Doctor {
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: Url,
        #[arg(long)]
        coordinator_url: Option<Url>,
    },
    Pool {
        #[command(subcommand)]
        command: PoolCommand,
    },
    Round {
        #[command(subcommand)]
        command: RoundCommand,
    },
    Ticket {
        #[command(subcommand)]
        command: TicketCommand,
    },
    Proof {
        #[command(subcommand)]
        command: ProofCommand,
    },
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
    Observe {
        #[arg(long)]
        input: PathBuf,
    },
    Evaluate(EvaluateArgs),
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_directory: Option<PathBuf>,
    },
    Evidence {
        #[arg(long, default_value = "evidence/generated")]
        output: PathBuf,
    },
    Coordinator {
        #[command(subcommand)]
        command: CoordinatorCommand,
    },
}
#[derive(Subcommand)]
enum PoolCommand {
    Create {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        authority: String,
        #[arg(long, default_value_t = 10)]
        minimum: u32,
        #[arg(long, default_value_t = 1000)]
        maximum: u32,
        #[arg(long, value_enum, default_value_t = BackendArg::Merkle)]
        backend: BackendArg,
        #[arg(long, default_value_t = 100)]
        registration_slots: u64,
        #[arg(long, default_value_t = 4)]
        execution_window_slots: u64,
    },
    Inspect {
        #[arg(long)]
        config: PathBuf,
    },
}
#[derive(Subcommand)]
enum RoundCommand {
    Open {
        #[arg(long)]
        pool: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        round_id: u64,
        #[arg(long)]
        current_slot: Option<u64>,
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: Url,
    },
    Inspect {
        #[arg(long)]
        config: PathBuf,
    },
}
#[derive(Subcommand)]
enum TicketCommand {
    Create {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Submit {
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        coordinator_url: Url,
    },
}
#[derive(Subcommand)]
enum ProofCommand {
    Verify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        root: String,
        #[arg(long)]
        round_id: u64,
    },
}
#[derive(Subcommand)]
enum ActionCommand {
    Prepare {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Simulate {
        #[arg(long)]
        action: PathBuf,
    },
    Execute {
        #[arg(long)]
        action: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        enable_sending: bool,
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: Url,
        #[arg(long)]
        window_start: u64,
        #[arg(long)]
        window_end: u64,
    },
}
#[derive(Subcommand)]
enum CoordinatorCommand {
    Run {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        pool_id: String,
        #[arg(long)]
        template_hash: String,
        #[arg(long)]
        round_id: u64,
        #[arg(long, default_value_t = 10)]
        minimum: u32,
        #[arg(long, default_value_t = 1000)]
        maximum: u32,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8899")]
        rpc_url: Url,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Transparent,
    Merkle,
}
#[derive(Args)]
struct EvaluateArgs {
    #[arg(long, default_value_t = 1000)]
    participants: u32,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(long, default_value_t = 4)]
    window_slots: u64,
    #[arg(long, default_value_t = 0.1)]
    dropout_rate: f64,
    #[arg(long, value_enum, default_value_t=BackendArg::Merkle)]
    backend: BackendArg,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    match Cli::parse().command {
        Command::Init { directory } => {
            if directory.exists() {
                bail!("refusing to overwrite {}", directory.display());
            }
            fs::create_dir_all(directory.join("tickets"))?;
            fs::create_dir_all(directory.join("receipts"))?;
            fs::write(
                directory.join("README.txt"),
                "Private participant state. Never commit.\n",
            )?;
            println!("initialized={} sending_enabled=false", directory.display());
        }
        Command::Doctor {
            rpc_url,
            coordinator_url,
        } => doctor(&rpc_url, coordinator_url.as_ref()).await?,
        Command::Pool { command } => pool(command)?,
        Command::Round { command } => round(command).await?,
        Command::Ticket { command } => ticket(command).await?,
        Command::Proof { command } => {
            let ProofCommand::Verify {
                proof,
                root,
                round_id,
            } = command;
            let value: CohortProof = read_json(&proof)?;
            value.verify(parse_digest(&root)?, round_id)?;
            println!("proof_valid=true");
        }
        Command::Action { command } => action(command).await?,
        Command::Observe { input } => {
            println!("{}", fs::read_to_string(input)?);
            println!("public_observation_only=true");
        }
        Command::Evaluate(args) => evaluate_command(args)?,
        Command::Report {
            input,
            output_directory,
        } => report(&input, output_directory.as_ref())?,
        Command::Evidence { output } => println!(
            "cargo xtask evaluate --output {} && cargo xtask verify-evidence --directory {}",
            output.display(),
            output.display()
        ),
        Command::Coordinator { command } => coordinator(command).await?,
    }
    Ok(())
}

async fn doctor(rpc_url: &Url, coordinator_url: Option<&Url>) -> Result<()> {
    let loopback = matches!(
        rpc_url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    );
    if !loopback {
        bail!("canonical demo requires loopback RPC");
    }
    for command in ["rustc", "cargo", "solana", "solana-test-validator"] {
        let output = std::process::Command::new(command)
            .arg("--version")
            .output()?;
        if !output.status.success() {
            bail!("required command failed: {command}");
        }
        println!(
            "tool={} version={}",
            command,
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    let inspection = mirror_pool_client::inspect_rpc(rpc_url)?;
    println!(
        "rpc={} loopback=true identity={} genesis_hash={} software_version={} slot={} sending_permitted=false",
        rpc_url,
        inspection.identity,
        inspection.genesis_hash,
        inspection.software_version,
        inspection.slot
    );
    if let Some(url) = coordinator_url {
        let response = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?
            .get(url.join("health")?)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!(
                "coordinator health check failed with status {}",
                response.status()
            );
        }
        println!("coordinator={} reachable=true", url);
    }
    Ok(())
}

fn pool(command: PoolCommand) -> Result<()> {
    match command {
        PoolCommand::Create {
            output,
            authority,
            minimum,
            maximum,
            backend,
            registration_slots,
            execution_window_slots,
        } => {
            use std::str::FromStr as _;
            let authority = solana_pubkey::Pubkey::from_str(&authority)?;
            let memo =
                solana_pubkey::Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")?;
            let mut pool_id = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut pool_id);
            let mut config = PoolConfig {
                pool_id: Digest32(pool_id),
                version: SCHEMA_VERSION,
                governance: GovernancePolicy::SingleAuthority {
                    authority: authority.to_bytes(),
                },
                action_template_hash: Digest32::hash(b"action-template", b"memo-v1"),
                min_participants: minimum,
                max_participants: maximum,
                registration_duration_slots: registration_slots,
                min_release_delay_slots: 2,
                max_release_delay_slots: 50,
                execution_window_slots,
                max_timing_dispersion_slots: execution_window_slots,
                privacy_backend: match backend {
                    BackendArg::Transparent => PrivacyBackend::TransparentRegistry,
                    BackendArg::Merkle => PrivacyBackend::MerkleCohort,
                },
                allowed_clusters: BTreeSet::from([Cluster::Localnet]),
                allowed_program_ids: BTreeSet::from([memo.to_bytes()]),
                completion_policy: CompletionPolicy::RedactedReceipt,
                created_at_unix: chrono::Utc::now().timestamp(),
                configuration_hash: Digest32::default(),
            };
            config.configuration_hash = config.compute_hash()?;
            config.validate()?;
            write_new_json(&output, &config)?;
            println!(
                "pool_config={} pool_id={} configuration_hash={} backend={:?} localnet_only=true",
                output.display(),
                config.pool_id,
                config.configuration_hash,
                config.privacy_backend
            );
        }
        PoolCommand::Inspect { config } => {
            let value: PoolConfig = read_json(&config)?;
            value.validate()?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            println!(
                "valid=true privacy_limit=coordination_is_not_cryptographic_anonymity funds_custodied=false"
            );
        }
    }
    Ok(())
}

async fn round(command: RoundCommand) -> Result<()> {
    match command {
        RoundCommand::Open {
            pool,
            output,
            round_id,
            current_slot,
            rpc_url,
        } => {
            let config: PoolConfig = read_json(&pool)?;
            config.validate()?;
            let slot = match current_slot {
                Some(value) => value,
                None => mirror_pool_client::inspect_rpc(&rpc_url)?.slot,
            };
            let deadline = slot
                .checked_add(config.registration_duration_slots)
                .ok_or_else(|| anyhow::anyhow!("registration deadline overflow"))?;
            let value = Round {
                pool_id: config.pool_id,
                round_id,
                state: RoundState::Registration,
                registration_start_slot: slot,
                registration_deadline_slot: deadline,
                release_slot: None,
                execution_window_start: None,
                execution_window_end: None,
                expected_cohort_size: config.min_participants,
                accepted_cohort_size: 0,
                cohort_merkle_root: None,
                action_template_hash: config.action_template_hash,
                privacy_backend: config.privacy_backend,
                cancellation_reason: None,
                final_metrics_hash: None,
            };
            mirror_pool_client::verify_round_configuration(&config, &value)?;
            write_new_json(&output, &value)?;
            println!(
                "round_config={} pool_id={} round_id={} registration_start={} registration_deadline={} submitted=false",
                output.display(),
                value.pool_id,
                value.round_id,
                slot,
                deadline
            );
        }
        RoundCommand::Inspect { config } => {
            let value: Round = read_json(&config)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            println!(
                "state={:?} threshold={} accepted={} root={} release_start={} release_end={}",
                value.state,
                value.expected_cohort_size,
                value.accepted_cohort_size,
                value
                    .cohort_merkle_root
                    .map_or_else(|| "none".to_owned(), |root| root.to_hex()),
                value
                    .execution_window_start
                    .map_or_else(|| "none".to_owned(), |slot| slot.to_string()),
                value
                    .execution_window_end
                    .map_or_else(|| "none".to_owned(), |slot| slot.to_string())
            );
        }
    }
    Ok(())
}

fn report(input: &PathBuf, output_directory: Option<&PathBuf>) -> Result<()> {
    let bytes = fs::read(input)?;
    let reports: Vec<EvaluationReport> = serde_json::from_slice(&bytes).or_else(|_| {
        serde_json::from_slice::<EvaluationReport>(&bytes).map(|report| vec![report])
    })?;
    if reports.is_empty() {
        bail!("evaluation report is empty");
    }
    let minimum_entropy = reports
        .iter()
        .map(|report| report.metrics.normalized_entropy)
        .fold(f64::INFINITY, f64::min);
    let maximum_auc = reports
        .iter()
        .map(|report| report.metrics.roc_auc)
        .fold(0.0_f64, f64::max);
    let markdown = format!(
        "# mirror-pool evaluation report\n\n- Scenarios: {}\n- Minimum normalized entropy: {:.6}\n- Maximum ROC AUC (unfavorable): {:.6}\n\nSynthetic evaluation does not prove anonymity or unlinkability.\n",
        reports.len(),
        minimum_entropy,
        maximum_auc
    );
    if let Some(directory) = output_directory {
        if directory.exists() {
            bail!("refusing to overwrite {}", directory.display());
        }
        fs::create_dir(directory)?;
        fs::write(
            directory.join("report.json"),
            serde_json::to_vec_pretty(&reports)?,
        )?;
        fs::write(directory.join("report.md"), &markdown)?;
        let mut writer = csv::Writer::from_path(directory.join("report.csv"))?;
        writer.write_record([
            "seed",
            "participants",
            "observed",
            "completion",
            "spread",
            "normalized_entropy",
            "minimum_k",
            "roc_auc",
            "trace_hash",
        ])?;
        for report in &reports {
            writer.write_record([
                report.scenario.seed.to_string(),
                report.scenario.participant_count.to_string(),
                report.metrics.observed_cohort_size.to_string(),
                report.metrics.completion_rate.to_string(),
                report.metrics.execution_spread_slots.to_string(),
                report.metrics.normalized_entropy.to_string(),
                report.metrics.minimum_k_anonymity.to_string(),
                report.metrics.roc_auc.to_string(),
                report.trace_hash.to_hex(),
            ])?;
        }
        writer.flush()?;
        println!(
            "report_directory={} formats=json,csv,markdown",
            directory.display()
        );
    } else {
        print!("{markdown}");
    }
    Ok(())
}

async fn action(command: ActionCommand) -> Result<()> {
    use mirror_pool_actions::{
        ActionParameters, ActionTemplateDriver, ComputeBudgetShapeTemplate,
        LocalStakeLifecycleTemplate, LocalTokenHousekeepingTemplate, MemoTemplate, PreparedAction,
    };
    use std::str::FromStr as _;
    let program = |value: &str| {
        solana_pubkey::Pubkey::from_str(value)
            .map(|key| key.to_bytes())
            .map_err(anyhow::Error::from)
    };
    match command {
        ActionCommand::Prepare { config, output } => {
            let parameters: ActionParameters = read_json(&config)?;
            let prepared = match &parameters {
                ActionParameters::Memo { .. } => MemoTemplate {
                    memo_program_id: program("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")?,
                }
                .prepare(&parameters)?,
                ActionParameters::ComputeBudget { .. } => ComputeBudgetShapeTemplate {
                    compute_budget_program_id: program(
                        "ComputeBudget111111111111111111111111111111",
                    )?,
                }
                .prepare(&parameters)?,
                ActionParameters::LocalTokenHousekeeping { .. } => LocalTokenHousekeepingTemplate {
                    token_program_id: program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?,
                }
                .prepare(&parameters)?,
                ActionParameters::LocalStakeLifecycle { .. } => LocalStakeLifecycleTemplate {
                    stake_program_id: program("Stake11111111111111111111111111111111111111")?,
                }
                .prepare(&parameters)?,
            };
            write_new_json(&output, &prepared)?;
            println!("prepared={} sent=false", output.display());
        }
        ActionCommand::Simulate { action } => {
            let prepared: PreparedAction = read_json(&action)?;
            let result = match prepared.template_id.as_str() {
                "memo-v1" => {
                    MemoTemplate {
                        memo_program_id: first_program_id(&prepared)?,
                    }
                    .simulate(&prepared)
                    .await?
                }
                "compute-budget-shape-v1" => {
                    ComputeBudgetShapeTemplate {
                        compute_budget_program_id: first_program_id(&prepared)?,
                    }
                    .simulate(&prepared)
                    .await?
                }
                "local-token-housekeeping-v1" => {
                    LocalTokenHousekeepingTemplate {
                        token_program_id: first_program_id(&prepared)?,
                    }
                    .simulate(&prepared)
                    .await?
                }
                "local-stake-lifecycle-v1" => {
                    LocalStakeLifecycleTemplate {
                        stake_program_id: first_program_id(&prepared)?,
                    }
                    .simulate(&prepared)
                    .await?
                }
                _ => bail!("unknown action template"),
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ActionCommand::Execute {
            action,
            confirm,
            enable_sending,
            wallet,
            rpc_url,
            window_start,
            window_end,
        } => {
            if !confirm || !enable_sending {
                bail!("local sending requires --confirm and --enable-sending");
            }
            let prepared: PreparedAction = read_json(&action)?;
            let receipt = mirror_pool_client::execute_local_memo(
                &prepared,
                &wallet,
                &rpc_url,
                window_start,
                window_end,
                confirm,
                enable_sending,
            )?;
            println!(
                "transaction_signature={} confirmed_local_transaction=true observed_slot={} estimated_fee_lamports={}",
                receipt.signature, receipt.observed_slot, receipt.estimated_fee_lamports
            );
        }
    }
    Ok(())
}

fn first_program_id(action: &mirror_pool_actions::PreparedAction) -> Result<[u8; 32]> {
    action
        .program_ids
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("missing program id"))
}
async fn ticket(command: TicketCommand) -> Result<()> {
    match command {
        TicketCommand::Create { binding, output } => {
            let binding: TicketBindingFile = read_json(&binding)?;
            let secret = mirror_pool_crypto::CoordinationSecret::generate();
            let (ticket, nonce) = mirror_pool_client::create_join_ticket(
                &mut rand::rngs::OsRng,
                &secret.signing_key(),
                binding.binding,
                binding.expiry_slot,
            )
            .map_err(|error| anyhow::anyhow!(error))?;
            write_private(
                &output,
                &LocalTicket {
                    ticket,
                    coordination_secret: secret.0,
                    nonce: nonce.0,
                },
            )?;
            println!(
                "ticket_file={} mode=0600 secret_material_not_printed=true",
                output.display()
            );
        }
        TicketCommand::Submit {
            ticket,
            coordinator_url,
        } => {
            let bytes = fs::read(&ticket)?;
            let ticket: JoinTicket = serde_json::from_slice(&bytes).or_else(|_| {
                serde_json::from_slice::<LocalTicket>(&bytes).map(|local| local.ticket)
            })?;
            let response = reqwest::Client::new()
                .post(coordinator_url.join("v1/tickets")?)
                .json(&mirror_pool_coordinator::TicketSubmission { ticket })
                .send()
                .await?
                .error_for_status()?;
            println!("{}", response.text().await?);
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct TicketBindingFile {
    binding: TicketBinding,
    expiry_slot: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct LocalTicket {
    ticket: JoinTicket,
    coordination_secret: [u8; 32],
    nonce: [u8; 32],
}
fn evaluate_command(args: EvaluateArgs) -> Result<()> {
    let report = evaluate(Scenario {
        scenario_version: 1,
        seed: args.seed,
        participant_count: args.participants,
        backend: match args.backend {
            BackendArg::Transparent => PrivacyBackend::TransparentRegistry,
            BackendArg::Merkle => PrivacyBackend::MerkleCohort,
        },
        release_strategy: ReleaseStrategy::NarrowWindow,
        execution_window_slots: args.window_slots,
        dropout_rate: args.dropout_rate,
        longitudinal_periods: 1,
        observer_features: ObserverFeatures::default(),
    })?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = args.output {
        fs::write(path, &json)?;
    }
    println!("{json}");
    Ok(())
}
async fn coordinator(command: CoordinatorCommand) -> Result<()> {
    let CoordinatorCommand::Run {
        database,
        pool_id,
        template_hash,
        round_id,
        minimum,
        maximum,
        listen,
        rpc_url,
    } = command;
    let config = CoordinatorConfig {
        binding: TicketBinding {
            pool_id: parse_digest(&pool_id)?,
            round_id,
            action_template_hash: parse_digest(&template_hash)?,
        },
        listen,
        minimum_participants: minimum,
        maximum_participants: maximum,
        requests_per_minute: 120,
        max_body_bytes: 16 * 1024,
    };
    mirror_pool_coordinator::serve(
        Arc::new(Coordinator::new(config, Store::open(database)?)),
        Arc::new(mirror_pool_coordinator::RpcSlotSource::new(
            rpc_url.to_string(),
        )),
    )
    .await?;
    Ok(())
}
fn parse_digest(value: &str) -> Result<Digest32> {
    let bytes = hex::decode(value)?;
    Ok(Digest32(
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?,
    ))
}
fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_private<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_new_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
