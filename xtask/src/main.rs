#![forbid(unsafe_code)]
use anyhow::Result;
use clap::{Parser, Subcommand};
use mirror_pool_core::PrivacyBackend;
use mirror_pool_simulator::{ObserverFeatures, ReleaseStrategy, Scenario, evaluate};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    thread,
    time::Duration,
};

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Setup,
    Demo,
    FullDemo,
    Evaluate {
        #[arg(long, default_value = "evidence/generated")]
        output: PathBuf,
    },
    VerifyEvidence {
        #[arg(long, default_value = "evidence/generated")]
        directory: PathBuf,
    },
    CleanDemo,
}
#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Setup => setup_checks()?,
        Command::Demo => demo(25)?,
        Command::FullDemo => {
            full_demo().await?;
            merkle_benchmark(1_000)?;
        }
        Command::Evaluate { output } => generate(&output, None, true)?,
        Command::VerifyEvidence { directory } => verify(&directory)?,
        Command::CleanDemo => {
            println!("No repository-local secret or validator state is retained.")
        }
    }
    Ok(())
}
async fn full_demo() -> Result<()> {
    use ed25519_dalek::SigningKey;
    use mirror_pool_actions::{ActionParameters, ActionTemplateDriver, MemoTemplate};
    use mirror_pool_core::Digest32;
    use mirror_pool_crypto::{JoinTicket, TicketBinding};
    use mirror_pool_store::Store;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    let directory = tempfile::tempdir()?;
    let database = directory.path().join("coordinator.db");
    let pool_id = Digest32::hash(b"full-demo", b"pool");
    let template_hash = Digest32::hash(b"template", b"memo-v1");
    let binding = TicketBinding {
        pool_id,
        round_id: 1,
        action_template_hash: template_hash,
    };
    let mut store = Store::open(&database)?;
    let mut tickets = Vec::new();
    for index in 0..25_u8 {
        let mut rng = ChaCha20Rng::from_seed([index.saturating_add(1); 32]);
        let key = SigningKey::from_bytes(&[index.saturating_add(2); 32]);
        let (ticket, _) = JoinTicket::create(&mut rng, &key, pool_id, 1, template_hash, 10_000)?;
        ticket.verify(1, &binding)?;
        store.accept_ticket(&ticket)?;
        tickets.push(ticket);
    }
    let (root, included) = store.seal_cohort(pool_id, 1, 10)?;
    for ticket in &tickets {
        let commitment = ticket.commitment()?;
        store
            .proof(pool_id, 1, commitment)?
            .ok_or_else(|| anyhow::anyhow!("missing proof"))?
            .verify(root, 1)?;
    }
    store.schedule_release(pool_id, 1, 500, 504)?;

    let second_binding = TicketBinding {
        pool_id,
        round_id: 2,
        action_template_hash: template_hash,
    };
    for index in 0..10_u8 {
        let mut rng = ChaCha20Rng::from_seed([index.saturating_add(50); 32]);
        let key = SigningKey::from_bytes(&[index.saturating_add(70); 32]);
        let (ticket, _) = JoinTicket::create(&mut rng, &key, pool_id, 2, template_hash, 20_000)?;
        ticket.verify(2, &second_binding)?;
        store.accept_ticket(&ticket)?;
    }
    drop(store);
    let mut restarted = Store::open(&database)?;
    let (recovered_root, recovered_count) = restarted.seal_cohort(pool_id, 1, 10)?;
    anyhow::ensure!(
        (root, included) == (recovered_root, recovered_count),
        "root changed after restart"
    );
    restarted.schedule_release(pool_id, 1, 500, 504)?;
    let (_, second_included) = restarted.seal_cohort(pool_id, 2, 10)?;

    let report = evaluate(scenario(25, 7, PrivacyBackend::MerkleCohort, 0.08))?;
    let observed = report.metrics.observed_cohort_size;
    let memo_program: solana_pubkey::Pubkey =
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".parse()?;
    let action_template = MemoTemplate {
        memo_program_id: memo_program.to_bytes(),
    };
    let action = action_template.prepare(&ActionParameters::Memo {
        text: "mirror-pool-demo".to_owned(),
    })?;
    for _ in 0..observed {
        anyhow::ensure!(action_template.simulate(&action).await?.succeeded);
    }
    let local = run_localnet_demo(root, included, &action)?;
    let evidence = directory.path().join("evidence");
    generate(&evidence, Some(&local), false)?;
    verify(&evidence)?;
    println!(
        "virtual_participants=25 accepted_tickets={} included_tickets={} simulated_transactions={} submitted_transactions={} confirmed_local_transactions={} local_dropped_participants=1 dropped_participants={} failed_participants=0 restart_round=2 second_round_included={} root_consistent=true schedule_consistent=true onchain_root_consistent=true execution_spread_slots={} program_id={} deployment_signature={} receipt_hash={} trace_hash={}",
        tickets.len(),
        included,
        observed,
        local.submitted,
        local.confirmed,
        25 - observed,
        second_included,
        local.spread,
        local.program_id,
        local.deployment_signature,
        local.receipt_hash,
        report.trace_hash
    );
    Ok(())
}

struct LocalDemoResult {
    submitted: u32,
    confirmed: u32,
    spread: u64,
    program_id: solana_pubkey::Pubkey,
    deployment_signature: String,
    receipt_hash: mirror_pool_core::Digest32,
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn setup_checks() -> Result<()> {
    for (program, args) in [
        ("rustc", &["--version"][..]),
        ("cargo", &["--version"][..]),
        ("solana", &["--version"][..]),
        ("solana-test-validator", &["--version"][..]),
    ] {
        let output = ProcessCommand::new(program).args(args).output()?;
        anyhow::ensure!(
            output.status.success(),
            "required command failed: {program}"
        );
        println!(
            "dependency={} version={}",
            program,
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    let output = ProcessCommand::new("cargo")
        .args(["build-sbf", "--version"])
        .output()?;
    anyhow::ensure!(output.status.success(), "cargo-build-sbf is required");
    println!(
        "dependency=cargo-build-sbf version={}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

fn run_localnet_demo(
    root: mirror_pool_core::Digest32,
    included: u32,
    action: &mirror_pool_actions::PreparedAction,
) -> Result<LocalDemoResult> {
    use borsh::BorshDeserialize as _;
    use mirror_pool_client::{
        admin_round_instruction, begin_window_instruction, execute_local_memo,
        initialize_pool_instruction, open_round_instruction,
    };
    use mirror_pool_program::{Backend, CoordinationInstruction, RoundAccount, State};
    use solana_client::rpc_client::RpcClient;
    use solana_keypair::{Keypair, write_keypair_file};
    use solana_signer::Signer as _;
    use url::Url;

    setup_checks()?;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("workspace root unavailable"))?;
    let build = ProcessCommand::new("cargo")
        .current_dir(workspace)
        .args([
            "build-sbf",
            "--arch",
            "v3",
            "--manifest-path",
            "programs/mirror-pool-program/Cargo.toml",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(build.success(), "SBF build failed");
    let artifact = workspace.join("target/deploy/mirror_pool_program.so");
    anyhow::ensure!(artifact.is_file(), "SBF artifact missing");

    let directory = tempfile::tempdir()?;
    let authority = Keypair::new();
    let program = Keypair::new();
    let authority_path = directory.path().join("authority.json");
    let program_path = directory.path().join("program.json");
    write_keypair_file(&authority, &authority_path).map_err(|_| anyhow::anyhow!("key write"))?;
    write_keypair_file(&program, &program_path).map_err(|_| anyhow::anyhow!("key write"))?;
    let program_id = program.pubkey();

    let (rpc_port, faucet_port, gossip_port, dynamic_start, dynamic_end) = available_ports()?;
    let rpc_address = format!("http://127.0.0.1:{rpc_port}");
    let ledger = directory.path().join("validator-ledger");
    let child = ProcessCommand::new("solana-test-validator")
        .args([
            "--reset",
            "--quiet",
            "--ledger",
            &ledger.to_string_lossy(),
            "--rpc-port",
            &rpc_port.to_string(),
            "--faucet-port",
            &faucet_port.to_string(),
            "--gossip-port",
            &gossip_port.to_string(),
            "--dynamic-port-range",
            &format!("{dynamic_start}-{dynamic_end}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _validator = ChildGuard(child);
    wait_for_validator(&rpc_address)?;

    let airdrop = ProcessCommand::new("solana")
        .args([
            "--url",
            &rpc_address,
            "airdrop",
            "20",
            &authority.pubkey().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(airdrop.success(), "authority airdrop failed");
    let deploy = ProcessCommand::new("solana")
        .current_dir(workspace)
        .args([
            "program",
            "deploy",
            "--url",
            &rpc_address,
            "--keypair",
            &authority_path.to_string_lossy(),
            "--program-id",
            &program_path.to_string_lossy(),
            &artifact.to_string_lossy(),
        ])
        .output()?;
    anyhow::ensure!(deploy.status.success(), "program deployment failed");
    let deploy_output = String::from_utf8(deploy.stdout)?;
    let deployment_signature = deploy_output
        .lines()
        .find_map(|line| line.strip_prefix("Signature: "))
        .ok_or_else(|| anyhow::anyhow!("deployment signature missing"))?
        .to_owned();

    let rpc = RpcClient::new_with_commitment(
        rpc_address.clone(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    let mut participant_paths = Vec::new();
    for index in 0..6_u8 {
        let participant = Keypair::new();
        let path = directory.path().join(format!("participant-{index}.json"));
        write_keypair_file(&participant, &path).map_err(|_| anyhow::anyhow!("key write"))?;
        let funded = ProcessCommand::new("solana")
            .args([
                "--url",
                &rpc_address,
                "airdrop",
                "1",
                &participant.pubkey().to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        anyhow::ensure!(funded.success(), "participant airdrop failed");
        participant_paths.push(path);
    }

    let pool_id = mirror_pool_core::Digest32::hash(b"full-demo-onchain", b"pool").0;
    let template_hash = mirror_pool_core::Digest32::hash(b"template", b"memo-v1").0;
    let (initialize, pool) = initialize_pool_instruction(
        program_id,
        authority.pubkey(),
        pool_id,
        template_hash,
        10,
        50,
        2,
        50,
        30,
        Backend::MerkleCohort,
    )?;
    println!(
        "localnet_step=initialize_pool authority_exists={} program_exists={} system_exists={} pool_exists={}",
        rpc.get_account(&authority.pubkey()).is_ok(),
        rpc.get_account(&program_id).is_ok(),
        rpc.get_account(&solana_system_interface::program::ID)
            .is_ok(),
        rpc.get_account(&pool).is_ok()
    );
    send_instruction(&rpc, &authority, initialize)?;
    let slot = rpc.get_slot()?;
    let (open, round) = open_round_instruction(
        program_id,
        authority.pubkey(),
        pool,
        0,
        slot.saturating_add(1_000),
        template_hash,
    )?;
    println!("localnet_step=open_round");
    send_instruction(&rpc, &authority, open)?;
    println!("localnet_step=publish_root");
    send_instruction(
        &rpc,
        &authority,
        admin_round_instruction(
            program_id,
            authority.pubkey(),
            pool,
            round,
            CoordinationInstruction::PublishCohortRoot {
                root: root.0,
                accepted_count: included,
            },
        )?,
    )?;
    println!("localnet_step=seal_round");
    send_instruction(
        &rpc,
        &authority,
        admin_round_instruction(
            program_id,
            authority.pubkey(),
            pool,
            round,
            CoordinationInstruction::SealRound,
        )?,
    )?;
    let release_slot = rpc.get_slot()?.saturating_add(10);
    println!("localnet_step=schedule_release");
    send_instruction(
        &rpc,
        &authority,
        admin_round_instruction(
            program_id,
            authority.pubkey(),
            pool,
            round,
            CoordinationInstruction::ScheduleRelease { release_slot },
        )?,
    )?;
    wait_for_slot(&rpc, release_slot)?;
    println!("localnet_step=begin_window");
    send_instruction(
        &rpc,
        &authority,
        begin_window_instruction(program_id, round)?,
    )?;

    let rpc_url = Url::parse(&rpc_address)?;
    let window_end = release_slot.saturating_add(30);
    let mut slots = Vec::new();
    let mut signatures = Vec::new();
    for path in participant_paths.iter().take(5) {
        let receipt =
            execute_local_memo(action, path, &rpc_url, release_slot, window_end, true, true)?;
        slots.push(receipt.observed_slot);
        signatures.extend_from_slice(receipt.signature.as_bytes());
    }
    let account = rpc.get_account(&round)?;
    let mut account_data = &account.data[..];
    let onchain = RoundAccount::deserialize(&mut account_data)?;
    anyhow::ensure!(
        onchain.cohort_root == root.0
            && onchain.accepted_count == included
            && onchain.state == State::ExecutionWindow,
        "on-chain round verification failed"
    );
    let minimum = slots.iter().copied().min().unwrap_or(0);
    let maximum = slots.iter().copied().max().unwrap_or(0);
    Ok(LocalDemoResult {
        submitted: u32::try_from(slots.len())?,
        confirmed: u32::try_from(slots.len())?,
        spread: maximum.saturating_sub(minimum),
        program_id,
        deployment_signature,
        receipt_hash: mirror_pool_core::Digest32::hash(b"local-receipts", &signatures),
    })
}

fn send_instruction(
    rpc: &solana_client::rpc_client::RpcClient,
    signer: &solana_keypair::Keypair,
    instruction: solana_instruction::Instruction,
) -> Result<String> {
    use solana_signer::Signer as _;
    let blockhash = rpc.get_latest_blockhash()?;
    let transaction = solana_transaction::Transaction::new_signed_with_payer(
        &[instruction],
        Some(&signer.pubkey()),
        &[signer],
        blockhash,
    );
    let simulation = rpc.simulate_transaction(&transaction)?;
    anyhow::ensure!(
        simulation.value.err.is_none(),
        "coordination simulation failed: {:?}; logs={:?}",
        simulation.value.err,
        simulation.value.logs
    );
    Ok(rpc.send_and_confirm_transaction(&transaction)?.to_string())
}

fn wait_for_slot(rpc: &solana_client::rpc_client::RpcClient, target: u64) -> Result<()> {
    for _ in 0..200 {
        if rpc.get_slot()? >= target {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("release slot timed out")
}

fn wait_for_validator(rpc_address: &str) -> Result<()> {
    for _ in 0..200 {
        let ready = ProcessCommand::new("solana")
            .args(["--url", rpc_address, "cluster-version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if ready {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("local validator startup timed out")
}

fn available_ports() -> Result<(u16, u16, u16, u16, u16)> {
    for base in (18_000_u16..45_000_u16).step_by(80) {
        let end = base.saturating_add(69);
        let listeners = (base..=end)
            .map(|port| TcpListener::bind(("127.0.0.1", port)))
            .collect::<Result<Vec<_>, _>>();
        if listeners.is_ok() {
            return Ok((
                base,
                base.saturating_add(2),
                base.saturating_add(3),
                base.saturating_add(10),
                end,
            ));
        }
    }
    anyhow::bail!("no isolated local validator port range available")
}

fn demo(count: u32) -> Result<()> {
    let report = evaluate(scenario(count, 7, PrivacyBackend::MerkleCohort, 0.08))?;
    println!(
        "virtual_participants={} observed={} trace_hash={} confirmed_local_transactions=0",
        count, report.metrics.observed_cohort_size, report.trace_hash
    );
    Ok(())
}
fn merkle_benchmark(count: u32) -> Result<()> {
    use std::time::Instant;
    let leaves = (0..count)
        .map(|index| mirror_pool_core::Digest32::hash(b"benchmark-leaf", &index.to_le_bytes()))
        .collect();
    let started = Instant::now();
    let tree = mirror_pool_merkle::MerkleCohort::build(leaves)?;
    let build = started.elapsed();
    let leaf = mirror_pool_core::Digest32::hash(b"benchmark-leaf", &(count / 2).to_le_bytes());
    let started = Instant::now();
    let proof = tree.proof(leaf, 1)?;
    let generation = started.elapsed();
    let root = tree.root()?;
    let started = Instant::now();
    proof.verify(root, 1)?;
    let verification = started.elapsed();
    println!(
        "merkle_participants={count} root={root} build_us={} proof_generation_us={} proof_verification_us={}",
        build.as_micros(),
        generation.as_micros(),
        verification.as_micros()
    );
    Ok(())
}
fn generate(path: &Path, local: Option<&LocalDemoResult>, print_path: bool) -> Result<()> {
    fs::create_dir_all(path)?;
    let mut reports = Vec::new();
    for round in 0..120_u64 {
        let mut value = scenario(
            [10, 100, 1_000][round as usize % 3],
            [7, 42, 99][round as usize / 3 % 3] + round,
            if round % 2 == 0 {
                PrivacyBackend::TransparentRegistry
            } else {
                PrivacyBackend::MerkleCohort
            },
            if round % 5 == 0 { 0.35 } else { 0.05 },
        );
        value.release_strategy = [
            ReleaseStrategy::FixedSlot,
            ReleaseStrategy::NarrowWindow,
            ReleaseStrategy::RandomizedWithinWindow,
            ReleaseStrategy::LatencyAware,
        ][round as usize % 4];
        value.execution_window_slots = if round % 3 == 0 { 20 } else { 4 };
        value.longitudinal_periods = if round % 4 == 0 { 10 } else { 1 };
        reports.push(evaluate(value)?);
    }
    let full = ObserverFeatures::default();
    let ablations = [
        ObserverFeatures {
            timing: false,
            ..full.clone()
        },
        ObserverFeatures {
            instruction_shape: false,
            ..full.clone()
        },
        ObserverFeatures {
            fee_behavior: false,
            ..full.clone()
        },
        ObserverFeatures {
            funding_graph: false,
            ..full.clone()
        },
        ObserverFeatures {
            amount_bucket: false,
            ..full.clone()
        },
        ObserverFeatures {
            historical_behavior: false,
            ..full
        },
    ];
    let mut control = scenario(1_000, 10_000, PrivacyBackend::MerkleCohort, 0.1);
    control.longitudinal_periods = 10;
    reports.push(evaluate(control)?);
    for features in ablations {
        let mut value = scenario(1_000, 10_000, PrivacyBackend::MerkleCohort, 0.1);
        value.longitudinal_periods = 10;
        value.observer_features = features;
        reports.push(evaluate(value)?);
    }
    let json = serde_json::to_vec_pretty(&reports)?;
    fs::write(path.join("evaluation.json"), &json)?;
    let mut writer = csv::Writer::from_path(path.join("evaluation.csv"))?;
    writer.write_record([
        "version",
        "seed",
        "participants",
        "backend",
        "strategy",
        "window",
        "dropout",
        "observed",
        "completion",
        "spread",
        "entropy",
        "effective_set",
        "k",
        "auc",
        "fpr",
        "fnr",
        "trace_hash",
    ])?;
    for r in &reports {
        writer.write_record([
            r.scenario.scenario_version.to_string(),
            r.scenario.seed.to_string(),
            r.scenario.participant_count.to_string(),
            format!("{:?}", r.scenario.backend),
            format!("{:?}", r.scenario.release_strategy),
            r.scenario.execution_window_slots.to_string(),
            r.scenario.dropout_rate.to_string(),
            r.metrics.observed_cohort_size.to_string(),
            r.metrics.completion_rate.to_string(),
            r.metrics.execution_spread_slots.to_string(),
            r.metrics.shannon_entropy.to_string(),
            r.metrics.effective_anonymity_set.to_string(),
            r.metrics.minimum_k_anonymity.to_string(),
            r.metrics.roc_auc.to_string(),
            r.metrics.false_positive_rate.to_string(),
            r.metrics.false_negative_rate.to_string(),
            r.trace_hash.to_hex(),
        ])?;
    }
    writer.flush()?;
    let minimum_entropy = reports
        .iter()
        .map(|r| r.metrics.normalized_entropy)
        .fold(f64::INFINITY, f64::min);
    let maximum_auc = reports
        .iter()
        .map(|r| r.metrics.roc_auc)
        .fold(0.0_f64, f64::max);
    fs::write(
        path.join("evaluation.md"),
        format!(
            "# Synthetic adversarial evaluation\n\n- Scenarios: {} (120 multi-round baselines + 1 ablation control + 6 same-seed feature ablations)\n- Cohort sizes: 10, 100, and 1,000 virtual participants\n- Minimum normalized entropy: {minimum_entropy:.6}\n- Maximum adversarial AUC (unfavorable): {maximum_auc:.6}\n\nSynthetic results do not prove real-world anonymity. Larger announced cohorts are not automatically larger observed anonymity sets; dropouts and unique features reduce the effective set. Synchronization can itself be a detectable fingerprint.\n",
            reports.len()
        ),
    )?;
    let csv = fs::read(path.join("evaluation.csv"))?;
    let md = fs::read(path.join("evaluation.md"))?;
    fs::write(
        path.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "scenario_count": reports.len(),
            "pool_count": 1,
            "round_count": 120,
            "local_submitted_transactions": local.map_or(0, |value| value.submitted),
            "local_confirmed_transactions": local.map_or(0, |value| value.confirmed),
            "local_execution_spread_slots": local.map_or(0, |value| value.spread),
            "evaluation_json_blake3": blake3::hash(&json).to_hex().to_string(),
            "evaluation_csv_blake3": blake3::hash(&csv).to_hex().to_string(),
            "evaluation_md_blake3": blake3::hash(&md).to_hex().to_string()
        }))?,
    )?;
    if print_path {
        println!("generated={} scenarios={}", path.display(), reports.len());
    } else {
        println!(
            "generated_sanitized_evidence=true scenarios={}",
            reports.len()
        );
    }
    Ok(())
}
fn verify(path: &Path) -> Result<()> {
    let json = fs::read(path.join("evaluation.json"))?;
    let csv = fs::read(path.join("evaluation.csv"))?;
    let md = fs::read(path.join("evaluation.md"))?;
    let manifest_bytes = fs::read(path.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    anyhow::ensure!(manifest["version"] == 1);
    anyhow::ensure!(manifest["scenario_count"].as_u64().unwrap_or(0) >= 127);
    anyhow::ensure!(manifest["pool_count"].as_u64().unwrap_or(0) >= 1);
    anyhow::ensure!(manifest["round_count"].as_u64().unwrap_or(0) >= 120);
    anyhow::ensure!(manifest["evaluation_json_blake3"] == blake3::hash(&json).to_hex().as_str());
    anyhow::ensure!(manifest["evaluation_csv_blake3"] == blake3::hash(&csv).to_hex().as_str());
    anyhow::ensure!(manifest["evaluation_md_blake3"] == blake3::hash(&md).to_hex().as_str());
    let submitted = manifest["local_submitted_transactions"]
        .as_u64()
        .unwrap_or(0);
    let confirmed = manifest["local_confirmed_transactions"]
        .as_u64()
        .unwrap_or(0);
    let spread = manifest["local_execution_spread_slots"]
        .as_u64()
        .unwrap_or(0);
    anyhow::ensure!(confirmed <= submitted);
    anyhow::ensure!(confirmed >= 2 || spread == 0);
    let text = format!(
        "{}{}{}{}",
        String::from_utf8_lossy(&json),
        String::from_utf8_lossy(&csv),
        String::from_utf8_lossy(&md),
        String::from_utf8_lossy(&manifest_bytes)
    )
    .to_lowercase();
    for pattern in ["seed phrase", "private key", "passphrase", "/users/"] {
        anyhow::ensure!(!text.contains(pattern), "sensitive pattern: {pattern}");
    }
    println!("evidence_valid=true");
    Ok(())
}
fn scenario(count: u32, seed: u64, backend: PrivacyBackend, dropout: f64) -> Scenario {
    Scenario {
        scenario_version: 1,
        seed,
        participant_count: count,
        backend,
        release_strategy: ReleaseStrategy::NarrowWindow,
        execution_window_slots: 4,
        dropout_rate: dropout,
        longitudinal_periods: 1,
        observer_features: ObserverFeatures::default(),
    }
}
