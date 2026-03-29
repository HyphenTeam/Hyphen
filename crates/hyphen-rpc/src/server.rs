use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::handler::RpcHandler;
use crate::messages::{RpcRequest, RpcResponse};

const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

pub struct RpcServer {
    handler: Arc<RpcHandler>,
    listener: TcpListener,
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
        })
    }

    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&self.handler);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, handler).await {
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

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

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

        let response = handler.handle_request(&request);
        let resp_bytes = response.encode_to_vec();
        stream.write_u32(resp_bytes.len() as u32).await?;
        stream.write_all(&resp_bytes).await?;
    }
}
