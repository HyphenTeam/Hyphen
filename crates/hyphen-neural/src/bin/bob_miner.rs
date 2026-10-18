//! `bob-miner`: the reference prover for the Alice neural challenge.
//!
//! The binary is intentionally small and self-contained. It derives the same
//! challenge the contract derives, searches for a preimage with the deterministic
//! gradient-descent prover, and verifies its own answer before printing it, so a
//! submission is never produced without a local acceptance check.

use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use hyphen_neural::challenge::Verification;
use hyphen_neural::{
    decode_descriptor, encode_descriptor, solve, verify, ChallengeDescriptor, MlpSpec, SolveConfig,
    DEFAULT_INPUT_DIM, DEFAULT_OUTPUT_DIM, DEFAULT_TOLERANCE_ULP, DESCRIPTOR_BYTES,
};

#[derive(Parser, Debug)]
#[command(
    name = "bob-miner",
    about = "Deterministic prover for the Hyphen Alice neural challenge"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the descriptor and target for one epoch.
    Challenge {
        #[command(flatten)]
        challenge: ChallengeArgs,
        /// Emit JSON instead of key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// Search for a preimage and verify it locally.
    Solve {
        #[command(flatten)]
        challenge: ChallengeArgs,
        /// Levenberg-Marquardt iterations per restart.
        #[arg(long, default_value_t = 256)]
        iterations: u64,
        /// Initial damping in Q32.32 (`2^32 = 1.0`).
        #[arg(long, default_value_t = 134_217_728)]
        damping: i64,
        /// Deterministic restarts.
        #[arg(long, default_value_t = 32)]
        restarts: u32,
        /// Emit JSON instead of key=value lines.
        #[arg(long)]
        json: bool,
    },
    /// Verify a candidate preimage against an epoch.
    Verify {
        #[command(flatten)]
        challenge: ChallengeArgs,
        /// Comma-separated Q32.32 values, or 64-character hex when prefixed with `0x`.
        #[arg(long)]
        solution: String,
        /// Also decode a descriptor supplied as hex instead of deriving it.
        #[arg(long)]
        descriptor_hex: Option<String>,
    },
    /// Decode a descriptor emitted by the contract.
    Decode {
        /// Hex-encoded descriptor.
        descriptor_hex: String,
    },
}

#[derive(clap::Args, Debug, Clone)]
struct ChallengeArgs {
    /// 32-byte chain seed as 64 hex characters. Required unless a descriptor is
    /// supplied directly.
    #[arg(long)]
    seed: Option<String>,
    /// Challenge epoch. Required unless a descriptor is supplied directly.
    #[arg(long)]
    epoch: Option<u64>,
    /// Hidden width, which is the difficulty axis.
    #[arg(long, default_value_t = 16)]
    hidden: u16,
    /// Input width.
    #[arg(long, default_value_t = DEFAULT_INPUT_DIM)]
    input: u16,
    /// Output width.
    #[arg(long, default_value_t = DEFAULT_OUTPUT_DIM)]
    output: u16,
    /// Acceptance tolerance in Q32.32 ulps.
    #[arg(long, default_value_t = DEFAULT_TOLERANCE_ULP)]
    tolerance: u64,
}

impl ChallengeArgs {
    fn descriptor(&self) -> Result<ChallengeDescriptor, String> {
        let seed = self
            .seed
            .as_deref()
            .ok_or_else(|| "--seed is required to derive a challenge".to_string())?;
        let epoch = self
            .epoch
            .ok_or_else(|| "--epoch is required to derive a challenge".to_string())?;
        let seed = decode_seed(seed)?;
        let descriptor = ChallengeDescriptor {
            version: hyphen_neural::DESCRIPTOR_VERSION,
            epoch,
            spec: MlpSpec {
                input_dim: self.input,
                hidden_dim: self.hidden,
                output_dim: self.output,
            },
            tolerance_ulp: self.tolerance,
            chain_seed: seed,
        };
        descriptor.validate().map_err(|error| error.to_string())?;
        Ok(descriptor)
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bob-miner: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Challenge { challenge, json } => {
            let descriptor = challenge.descriptor()?;
            let target = target_of(&descriptor)?;
            let mut encoded = [0u8; DESCRIPTOR_BYTES];
            encode_descriptor(&descriptor, &mut encoded).map_err(|e| e.to_string())?;
            let descriptor_hex = encode_hex(&encoded);
            if json {
                println!(
                    "{{\"epoch\":{},\"input_dim\":{},\"hidden_dim\":{},\"output_dim\":{},\"tolerance_ulp\":{},\"descriptor_hex\":\"{}\",\"target\":[{}]}}",
                    descriptor.epoch,
                    descriptor.spec.input_dim,
                    descriptor.spec.hidden_dim,
                    descriptor.spec.output_dim,
                    descriptor.tolerance_ulp,
                    descriptor_hex,
                    target
                        .iter()
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            } else {
                println!("epoch={}", descriptor.epoch);
                println!("input_dim={}", descriptor.spec.input_dim);
                println!("hidden_dim={}", descriptor.spec.hidden_dim);
                println!("output_dim={}", descriptor.spec.output_dim);
                println!("tolerance_ulp={}", descriptor.tolerance_ulp);
                println!("descriptor_hex={descriptor_hex}");
                println!(
                    "target={}",
                    target
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            Ok(())
        }
        Command::Solve {
            challenge,
            iterations,
            damping,
            restarts,
            json,
        } => {
            let descriptor = challenge.descriptor()?;
            let config = SolveConfig {
                max_iterations: iterations,
                damping,
                restarts,
            };
            let started = Instant::now();
            let outcome = solve(&descriptor, config).map_err(|error| error.to_string())?;
            let elapsed = started.elapsed();
            let verification = verify(&descriptor, &outcome.input).map_err(|e| e.to_string())?;
            if !verification.accepted {
                return Err(format!(
                    "search finished after {:.3}s without meeting tolerance (max_error={} tolerance={})",
                    elapsed.as_secs_f64(),
                    verification.max_error,
                    descriptor.tolerance_ulp
                ));
            }
            if json {
                println!(
                    "{{\"accepted\":true,\"epoch\":{},\"hidden_dim\":{},\"restart\":{},\"iterations\":{},\"max_error\":{},\"tolerance_ulp\":{},\"elapsed_seconds\":{:.3},\"solution\":[{}]}}",
                    descriptor.epoch,
                    descriptor.spec.hidden_dim,
                    outcome.restart,
                    outcome.iterations,
                    verification.max_error,
                    descriptor.tolerance_ulp,
                    elapsed.as_secs_f64(),
                    outcome.input.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")
                );
            } else {
                println!("accepted=true");
                println!("epoch={}", descriptor.epoch);
                println!("hidden_dim={}", descriptor.spec.hidden_dim);
                println!("restart={}", outcome.restart);
                println!("iterations={}", outcome.iterations);
                println!("max_error={}", verification.max_error);
                println!("tolerance_ulp={}", descriptor.tolerance_ulp);
                println!("elapsed_seconds={:.3}", elapsed.as_secs_f64());
                println!(
                    "solution={}",
                    outcome
                        .input
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            Ok(())
        }
        Command::Verify {
            challenge,
            solution,
            descriptor_hex,
        } => {
            let descriptor = match descriptor_hex {
                Some(hex) => {
                    let bytes = decode_hex(&hex)?;
                    decode_descriptor(&bytes).map_err(|error| error.to_string())?
                }
                None => challenge.descriptor()?,
            };
            let values = parse_solution(&solution)?;
            let verification = verify(&descriptor, &values).map_err(|e| e.to_string())?;
            print_verification(&verification, descriptor.tolerance_ulp);
            if verification.accepted {
                Ok(())
            } else {
                Err("candidate does not meet the descriptor tolerance".into())
            }
        }
        Command::Decode { descriptor_hex } => {
            let bytes = decode_hex(&descriptor_hex)?;
            let descriptor = decode_descriptor(&bytes).map_err(|error| error.to_string())?;
            println!("version={}", descriptor.version);
            println!("epoch={}", descriptor.epoch);
            println!("input_dim={}", descriptor.spec.input_dim);
            println!("hidden_dim={}", descriptor.spec.hidden_dim);
            println!("output_dim={}", descriptor.spec.output_dim);
            println!("tolerance_ulp={}", descriptor.tolerance_ulp);
            println!("chain_seed={}", encode_hex(&descriptor.chain_seed));
            Ok(())
        }
    }
}

fn print_verification(verification: &Verification, tolerance: u64) {
    println!("accepted={}", verification.accepted);
    println!("max_error={}", verification.max_error);
    println!("mean_squared_error={}", verification.mean_squared_error);
    println!("tolerance_ulp={tolerance}");
}

fn target_of(descriptor: &ChallengeDescriptor) -> Result<Vec<i64>, String> {
    let layout = descriptor.spec.weight_layout();
    let mut weights = vec![0i64; layout.total];
    let mut input = vec![0i64; descriptor.spec.input_dim as usize];
    let mut hidden = vec![0i64; descriptor.spec.hidden_dim as usize];
    let mut target = vec![0i64; descriptor.spec.output_dim as usize];
    descriptor
        .derive_weights(&mut weights)
        .map_err(|error| error.to_string())?;
    descriptor
        .derive_preimage(&mut input)
        .map_err(|error| error.to_string())?;
    descriptor
        .derive_target(&weights, &input, &mut hidden, &mut target)
        .map_err(|error| error.to_string())?;
    Ok(target)
}

fn parse_solution(text: &str) -> Result<Vec<i64>, String> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        let bytes = decode_hex(hex)?;
        let mut values = vec![0i64; bytes.len() / 8];
        hyphen_neural::decode_values_into(&bytes, &mut values).map_err(|e| e.to_string())?;
        return Ok(values);
    }
    trimmed
        .split(',')
        .map(|value| {
            value
                .trim()
                .parse::<i64>()
                .map_err(|error| format!("invalid solution value '{value}': {error}"))
        })
        .collect()
}

fn decode_seed(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(text)?;
    if bytes.len() != 32 {
        return Err(format!(
            "seed must be 32 bytes (64 hex characters), got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err("hex input must have an even number of characters".into());
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let raw = text.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character '{}'", byte as char)),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn seeds_must_be_thirty_two_bytes() {
        assert!(decode_seed("00").is_err());
        assert!(decode_seed(&"00".repeat(32)).is_ok());
    }

    #[test]
    fn solutions_accept_decimal_and_hex() {
        assert_eq!(parse_solution("1,-2,3").unwrap(), vec![1, -2, 3]);
        let mut hex = String::from("0x");
        for value in [1i64, -2] {
            hex.push_str(&encode_hex(&value.to_le_bytes()));
        }
        assert_eq!(parse_solution(&hex).unwrap(), vec![1, -2]);
    }
}
