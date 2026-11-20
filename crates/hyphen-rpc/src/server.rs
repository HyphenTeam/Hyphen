use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::handler::RpcHandler;
use crate::messages::{RpcRequest, RpcResponse};

pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

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
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&self.handler);
                    let events = self.transaction_events.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, handler, events).await {
                            warn!("connection from {} closed: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {}", e);
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
        let len = match stream.read_u32().await {
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
            let resp_bytes = err_resp.encode_to_vec();
            stream.write_u32(resp_bytes.len() as u32).await?;
            stream.write_all(&resp_bytes).await?;
            return Err("frame too large".into());
        }

        let mut buf = Vec::with_capacity((len as usize).min(8192));
        if (&mut stream)
            .take(u64::from(len))
            .read_to_end(&mut buf)
            .await?
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
                let resp_bytes = err_resp.encode_to_vec();
                stream.write_u32(resp_bytes.len() as u32).await?;
                stream.write_all(&resp_bytes).await?;
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
        let resp_bytes = response.encode_to_vec();
        stream.write_u32(resp_bytes.len() as u32).await?;
        stream.write_all(&resp_bytes).await?;
    }
}
