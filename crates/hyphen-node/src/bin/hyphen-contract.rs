use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use hyphen_core::{ChainConfig, ChainIdentity, FROZEN_BLOCK_VERSION};
use hyphen_crypto::{Hash256, SecretKey, blake3_hash, hex_decode, hex_encode};
use hyphen_rpc::{messages::*, server::MAX_FRAME_SIZE};
use hyphen_vm::ledger::{SignedCall, SignedDeploy, VmTransaction};
use hyphen_vm::types::{ContractAddress, ContractCall, DeployParams};
use prost::Message;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(about = "Sign contract-devnet transactions and query canonical contract storage")]
struct Cli {
    /// Binary RPC endpoint on contract-devnet.
    #[arg(long, default_value = "127.0.0.1:48333")]
    rpc: SocketAddr,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Signer {
    /// File containing the raw 32-byte Ed25519 signing seed.
    #[arg(long)]
    key_file: PathBuf,
    /// Next VM transaction nonce of this signer, starting at zero.
    #[arg(long)]
    nonce: u64,
    #[arg(long, default_value_t = 10_000_000)]
    gas: u64,
    /// Raw constructor or call input. Omit for an empty byte string.
    #[arg(long)]
    input: Option<PathBuf>,
}

impl Signer {
    fn load(&self) -> Result<(SecretKey, Vec<u8>)> {
        if !hyphen_vm::gas::valid_transaction_gas(self.gas) {
            return Err("gas outside contract-devnet transaction limits".into());
        }
        let mut key = SecretKey([0; 32]);
        let mut file = File::open(&self.key_file)?;
        file.read_exact(&mut key.0)?;
        if file.read(&mut [0])? != 0 {
            return Err("expected a raw 32-byte signing seed".into());
        }
        let input = self
            .input
            .as_deref()
            .map(|path| read_bytes(path, hyphen_vm::host::MAX_IO_SIZE))
            .transpose()?
            .unwrap_or_default();
        Ok((key, input))
    }
}

#[derive(Subcommand)]
enum Command {
    Deploy {
        wasm: PathBuf,
        #[command(flatten)]
        signer: Signer,
    },
    Call {
        #[arg(value_parser = parse_address)]
        address: ContractAddress,
        function: String,
        #[command(flatten)]
        signer: Signer,
    },
    /// Print the canonical value of a hex-encoded storage key as hex.
    Storage {
        #[arg(value_parser = parse_address)]
        address: ContractAddress,
        key: String,
    },
    /// Execute a read-only export locally against one block's code and storage.
    Query {
        #[arg(value_parser = parse_address)]
        address: ContractAddress,
        #[arg(long, default_value = hyphen_vm::application::APP_QUERY_EXPORT)]
        function: String,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long, default_value_t = 10_000_000)]
        gas: u64,
    },
}

fn parse_address(text: &str) -> std::result::Result<ContractAddress, String> {
    let bytes = hex_decode(text).map_err(|e| e.to_string())?;
    Ok(ContractAddress(
        bytes.try_into().map_err(|_| "expected a 32-byte address")?,
    ))
}

fn read_bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds {limit} bytes", path.display()).into());
    }
    Ok(bytes)
}

fn request<R: Message + Default>(
    stream: &mut TcpStream,
    method: u32,
    message: impl Message,
) -> Result<R> {
    let payload = RpcRequest {
        id: method,
        method,
        payload: message.encode_to_vec(),
    }
    .encode_to_vec();
    stream.write_all(&u32::try_from(payload.len())?.to_be_bytes())?;
    stream.write_all(&payload)?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length);
    if length > MAX_FRAME_SIZE {
        return Err("RPC response exceeds the frame limit".into());
    }
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes)?;
    let response = RpcResponse::decode(bytes.as_slice())?;
    if response.id != method {
        return Err("unexpected RPC response ID".into());
    }
    if !response.success {
        return Err(response.error.into());
    }
    Ok(R::decode(response.payload.as_slice())?)
}

fn submit(
    stream: &mut TcpStream,
    transaction: VmTransaction,
    address: ContractAddress,
) -> Result<()> {
    let bytes = transaction.encode()?;
    let hash = blake3_hash(&bytes);
    println!("address={address}\ntransaction={hash}");
    let response: SubmitTransactionResponse = request(
        stream,
        METHOD_SUBMIT_TX,
        SubmitTransactionRequest { tx_data: bytes },
    )?;
    if !response.accepted {
        return Err(response.error.into());
    }
    if response.tx_hash != hash.as_bytes() {
        return Err("unexpected transaction hash from node".into());
    }
    println!("accepted=true");
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(30);
    let mut stream = TcpStream::connect_timeout(&cli.rpc, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let cfg = ChainConfig::contract_devnet();
    let identity = ChainIdentity::of(&cfg);
    let info: ChainInfoResponse =
        request(&mut stream, METHOD_GET_CHAIN_INFO, GetChainInfoRequest {})?;
    if info.network != cfg.network_name
        || info.consensus_params_hash != identity.consensus_params_hash
        || info.genesis_hash != identity.genesis_hash.as_bytes()
        || info.network_magic != identity.network_magic
        || info.block_version != FROZEN_BLOCK_VERSION
        || info.pouw_protocol_version != u32::from(hyphen_pow::POUW_PROTOCOL_VERSION)
    {
        return Err("node identity differs from contract-devnet".into());
    }
    let chain_id: Hash256 = identity.genesis_hash;
    match cli.command {
        Command::Deploy { wasm, signer } => {
            let (secret, constructor_args) = signer.load()?;
            let deployer = *secret.public_key().as_bytes();
            let address = ContractAddress::from_deployer_and_nonce(&deployer, signer.nonce);
            let params = DeployParams {
                deployer,
                code: read_bytes(&wasm, hyphen_vm::engine::MAX_CONTRACT_CODE_SIZE)?,
                constructor_args,
                gas_limit: signer.gas,
                nonce: signer.nonce,
            };
            submit(
                &mut stream,
                VmTransaction::Deploy(SignedDeploy::sign(chain_id, params, &secret)?),
                address,
            )
        }
        Command::Call {
            address,
            function,
            signer,
        } => {
            let (secret, args) = signer.load()?;
            let call = ContractCall {
                caller: *secret.public_key().as_bytes(),
                contract: address,
                function,
                args,
                gas_limit: signer.gas,
                value: 0,
            };
            submit(
                &mut stream,
                VmTransaction::Call(SignedCall::sign(chain_id, signer.nonce, call, &secret)?),
                address,
            )
        }
        Command::Storage { address, key } => {
            let key = hex_decode(&key)?;
            if key.len() > hyphen_vm::host::MAX_STORAGE_KEY_SIZE {
                return Err("storage key exceeds protocol limit".into());
            }
            let response: VmStorageResponse = request(
                &mut stream,
                METHOD_GET_VM_STORAGE,
                GetVmStorageRequest {
                    address: address.0.to_vec(),
                    key,
                },
            )?;
            if !response.found {
                return Err("storage key absent from canonical state".into());
            }
            println!("{}", hex_encode(response.value));
            Ok(())
        }
        Command::Query {
            address,
            function,
            input,
            gas,
        } => {
            let args = input
                .as_deref()
                .map(|path| read_bytes(path, hyphen_vm::host::MAX_IO_SIZE))
                .transpose()?
                .unwrap_or_default();
            let response: VmQuerySnapshotResponse = request(
                &mut stream,
                METHOD_GET_VM_QUERY_SNAPSHOT,
                GetVmContractRequest {
                    address: address.0.to_vec(),
                },
            )?;
            let snapshot: hyphen_vm::ledger::ContractSnapshot =
                hyphen_wire::wire_config(hyphen_vm::ledger::MAX_VM_TRANSACTION_BYTES)
                    .deserialize(&response.snapshot)?;
            if snapshot.contract.address != address || response.block_hash.len() != 32 {
                return Err("invalid query snapshot identity".into());
            }
            let output = snapshot.query(function, args, gas)?;
            println!(
                "block={}\nresult={}",
                hex_encode(response.block_hash),
                hex_encode(output)
            );
            Ok(())
        }
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
