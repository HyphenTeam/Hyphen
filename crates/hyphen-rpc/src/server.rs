use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::handler::RpcHandler;
use crate::messages::{RpcRequest, RpcResponse};

pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;
const FRAME_TIMEOUT: Duration = Duration::from_secs(90);

pub struct RpcServer {
    handler: Arc<RpcHandler>,
    listener: TcpListener,
    transaction_events: Option<tokio::sync::mpsc::Sender<hyphen_crypto::Hash256>>,
}

impl RpcServer {
    pub async fn bind(
        addr: &str,
        handler: RpcHandler,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        info!("RPC server listening on {}", addr);
        Ok(Self {
            handler: Arc::new(handler),
            listener,
            transaction_events: None,
        })
    }

    pub fn with_transaction_events(
        mut self,
        events: tokio::sync::mpsc::Sender<hyphen_crypto::Hash256>,
    ) -> Self {
        self.transaction_events = Some(events);
        self
    }

    pub async fn run(self) {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let incoming = tokio::select! {
                Some(done) = sessions.join_next(), if !sessions.is_empty() => {
                    if let Err(error) = done { warn!("RPC session stopped: {error}"); }
                    continue;
                }
                incoming = self.listener.accept(), if sessions.len() < MAX_CONNECTIONS => incoming,
            };
            match incoming {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&self.handler);
                    let events = self.transaction_events.clone();
                    sessions.spawn(async move {
                        if let Err(e) = handle_connection(stream, handler, events).await {
                            warn!("connection from {} closed: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    handler: Arc<RpcHandler>,
    events: Option<tokio::sync::mpsc::Sender<hyphen_crypto::Hash256>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
        let len = match tokio::time::timeout_at(deadline, stream.read_u32()).await? {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if len > MAX_FRAME_SIZE {
            let err_resp = RpcResponse {
                id: 0,
                success: false,
                payload: vec![],
                error: "frame too large".into(),
            };
            write_response(&mut stream, err_resp).await?;
            return Err("frame too large".into());
        }

        let mut buf = Vec::with_capacity((len as usize).min(8192));
        if tokio::time::timeout_at(
            deadline,
            (&mut stream).take(u64::from(len)).read_to_end(&mut buf),
        )
        .await??
            != len as usize
        {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }

        let request = match RpcRequest::decode(&buf[..]) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = RpcResponse {
                    id: 0,
                    success: false,
                    payload: vec![],
                    error: format!("decode error: {e}"),
                };
                write_response(&mut stream, err_resp).await?;
                continue;
            }
        };

        drop(buf);
        let response = handler.handle_request(&request);
        if request.method == crate::messages::METHOD_SUBMIT_TX
            && response.success
            && let Some(events) = &events
        {
            let submitted =
                crate::messages::SubmitTransactionResponse::decode(response.payload.as_slice())?;
            if submitted.accepted {
                let hash =
                    hyphen_crypto::Hash256::from_bytes(submitted.tx_hash.as_slice().try_into()?);
                let _ = events.send(hash).await;
            }
        }
        write_response(&mut stream, response).await?;
    }
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    response: RpcResponse,
) -> std::io::Result<()> {
    let response = if response.encoded_len() > MAX_FRAME_SIZE as usize {
        RpcResponse {
            id: response.id,
            success: false,
            payload: Vec::new(),
            error: "response exceeds frame limit".into(),
        }
    } else {
        response
    };
    let bytes = response.encode_to_vec();
    tokio::time::timeout(FRAME_TIMEOUT, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await
    })
    .await?
}
