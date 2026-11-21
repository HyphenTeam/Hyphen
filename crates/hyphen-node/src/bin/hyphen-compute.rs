mod common;
#[path = "hyphen-compute/reward.rs"]
mod reward;

use clap::{Parser, Subcommand};
use common::{Result, check_identity, parse_hash, read_bytes, request};
use hyphen_compute::inline::{
    InlineNeuralVerifier, MAX_INLINE_ENVELOPE, inline_circuit_id, inline_claim, inline_input,
};
use hyphen_compute::{
    ArithmeticProfile, ComputeTransaction, MIN_CHALLENGE_BLOCKS, MIN_RETENTION_BLOCKS,
    ProofVerifier, ScientificDomain, SignedResult, SignedTask, TaskRecord, TaskSpec, TaskStatus,
    neural_challenge_program_hash,
};
use hyphen_core::ChainConfig;
use hyphen_crypto::{Hash256, blake3_hash};
use hyphen_neural::{DESCRIPTOR_BYTES, decode_descriptor};
use hyphen_rpc::messages::*;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Publish and verify inline neural tasks on neural-devnet")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:48333")]
    rpc: SocketAddr,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fund and reconcile a publisher-authorized native payment for an inline task.
    Reward(reward::Reward),
    Publish {
        /// Raw 56-byte challenge descriptor.
        descriptor: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        nonce: u64,
        /// Last block height at which a worker may submit a solution.
        #[arg(long)]
        deadline: u64,
        /// Quoted net reward. The publisher can fund and pay it using the reward commands.
        #[arg(long)]
        reward: u64,
    },
    Submit {
        #[arg(value_parser = parse_hash)]
        task: Hash256,
        /// Raw descriptor followed by little-endian signed Q32.32 solution values.
        proof: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    Finalize {
        #[arg(value_parser = parse_hash)]
        task: Hash256,
    },
    /// Read the signed record, including the retained solution.
    Show {
        #[arg(value_parser = parse_hash)]
        task: Hash256,
        /// Read a stopped local neural-devnet database and report its checked tip on stderr.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Require the stopped database to match this independently selected tip.
        #[arg(long, requires = "data_dir", value_parser = parse_hash)]
        expect_tip: Option<Hash256>,
        /// Save the verified solution bytes of a finalized task to a new file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn show(record: &TaskRecord, output: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = output {
        use std::io::Write;
        let TaskStatus::Finalized { result, .. } = &record.status else {
            return Err("solution export requires a finalized task".into());
        };
        let bytes = result
            .claim
            .proof
            .get(DESCRIPTOR_BYTES..)
            .ok_or("missing solution")?;
        if blake3_hash(bytes) != result.claim.output.object_hash {
            return Err("solution digest differs from signed output".into());
        }
        let parent = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)?;
    }
    println!("{}", serde_json::to_string(record)?);
    Ok(())
}

fn read_task(stream: &mut TcpStream, task: Hash256, chain_id: Hash256) -> Result<TaskRecord> {
    let reply: ComputeTaskResponse = request(
        stream,
        METHOD_GET_COMPUTE_TASK,
        GetComputeTaskRequest {
            task_id: task.to_vec(),
        },
    )?;
    if !reply.found {
        return Err("task absent from canonical state".into());
    }
    let record: TaskRecord =
        hyphen_wire::wire_config(2 * MAX_INLINE_ENVELOPE).deserialize(&reply.record_data)?;
    verify_record(&record, task, chain_id)?;
    Ok(record)
}

fn verify_record(record: &TaskRecord, task: Hash256, chain_id: Hash256) -> Result<()> {
    let spec = &record.task.spec;
    if spec.id() != task || spec.circuit_id != inline_circuit_id() {
        return Err("task identity or inline circuit differs".into());
    }
    record.task.verify(chain_id, record.published_height)?;
    if record.published_height == 0 || !record.retention.is_empty() {
        return Err("invalid inline task record".into());
    }
    let result = match &record.status {
        TaskStatus::Open => return Ok(()),
        TaskStatus::Rejected { .. } => return Err("unexpected rejected inline task".into()),
        TaskStatus::Submitted {
            result,
            submitted_height,
            challenge_deadline,
        } => {
            if !(record.published_height..=spec.publish_deadline).contains(submitted_height)
                || submitted_height.checked_add(spec.challenge_blocks) != Some(*challenge_deadline)
            {
                return Err("invalid submission or challenge height".into());
            }
            result
        }
        TaskStatus::Finalized {
            result,
            finalized_height,
            retain_until_height,
        } => {
            if record
                .published_height
                .checked_add(spec.challenge_blocks)
                .is_none_or(|earliest_deadline| *finalized_height <= earliest_deadline)
                || finalized_height.checked_add(spec.retention_blocks) != Some(*retain_until_height)
            {
                return Err("invalid finalization or retention height".into());
            }
            result
        }
    };
    result.verify_signature()?;
    InlineNeuralVerifier.verify_execution(spec, &result.claim)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Reward(args) = cli.command {
        return args.run();
    }
    if let Command::Show {
        task,
        data_dir: Some(path),
        expect_tip,
        output,
    } = &cli.command
    {
        let db = common::checked_local_state(path, *expect_tip)?;
        let record = db
            .compute_task(*task)
            .ok_or("task absent from canonical state")?;
        verify_record(&record, *task, db.chain_id())?;
        return show(&record, output.as_deref());
    }
    let timeout = Duration::from_secs(30);
    let mut stream = TcpStream::connect_timeout(&cli.rpc, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let chain_id = check_identity(&mut stream, &ChainConfig::neural_devnet())?;
    let (id, transaction) = match cli.command {
        Command::Reward(_) => unreachable!(),
        Command::Publish {
            descriptor,
            key_file,
            nonce,
            deadline,
            reward,
        } => {
            let bytes = read_bytes(&descriptor, DESCRIPTOR_BYTES)?;
            let descriptor = decode_descriptor(&bytes)?;
            let signer = common::read_key(&key_file)?;
            let spec = TaskSpec {
                chain_id,
                scientist: signer.public_key(),
                nonce,
                domain: ScientificDomain::Connectomics,
                arithmetic: ArithmeticProfile::DeterministicFixedPointV1,
                circuit_id: inline_circuit_id(),
                program_hash: neural_challenge_program_hash(&descriptor)?,
                input: inline_input(&descriptor)?,
                max_operations: hyphen_compute::inline::forward_operations(descriptor.spec),
                challenge_blocks: MIN_CHALLENGE_BLOCKS,
                retention_blocks: MIN_RETENTION_BLOCKS,
                reward,
                publish_deadline: deadline,
            };
            (
                spec.id(),
                ComputeTransaction::Publish(SignedTask::sign(spec, &signer)?),
            )
        }
        Command::Submit {
            task,
            proof,
            key_file,
        } => {
            let record = read_task(&mut stream, task, chain_id)?;
            let signer = common::read_key(&key_file)?;
            let claim = inline_claim(
                &record.task.spec,
                signer.public_key(),
                &read_bytes(&proof, MAX_INLINE_ENVELOPE)?,
            )?;
            (
                task,
                ComputeTransaction::Submit(SignedResult::sign(claim, &signer)?),
            )
        }
        Command::Finalize { task } => (task, ComputeTransaction::Finalize { task_id: task }),
        Command::Show { task, output, .. } => {
            return show(&read_task(&mut stream, task, chain_id)?, output.as_deref());
        }
    };
    let bytes = transaction.encode()?;
    let hash = blake3_hash(&bytes);
    let reply: SubmitTransactionResponse = request(
        &mut stream,
        METHOD_SUBMIT_TX,
        SubmitTransactionRequest { tx_data: bytes },
    )?;
    if !reply.accepted {
        return Err(reply.error.into());
    }
    if reply.tx_hash != hash.as_bytes() {
        return Err("RPC transaction hash differs".into());
    }
    println!("task={id}\ntransaction={hash}");
    Ok(())
}
