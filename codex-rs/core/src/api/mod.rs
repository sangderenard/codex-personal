use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{CodexErr, Result};

pub async fn accept_with_retries(listener: TcpListener, tries: usize, retry: Duration) -> Result<(String, Option<TcpStream>)> {
    let mut attempts = 0usize;
    loop {
        if attempts >= tries {
            return Ok(("No response on the API".to_string(), None));
        }
        attempts += 1;
        match timeout(retry, listener.accept()).await {
            Ok(Ok((mut stream, _))) => {
                let mut compiled = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    compiled.extend_from_slice(&buf[..n]);
                    if n < buf.len() {
                        break;
                    }
                }
                let msg = if compiled.is_empty() {
                    "No handshake could be completed".to_string()
                } else {
                    String::from_utf8_lossy(&compiled).replace('\n', " ")
                };
                return Ok((msg, Some(stream)));
            }
            Ok(Err(e)) => return Err(CodexErr::Io(e)),
            Err(_) => {
                tracing::info!("Waiting for API handshake attempt {}", attempts);
            }
        }
    }
}

pub async fn send_payload(mut stream: TcpStream, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    Ok(resp)
}
