//! Length-prefixed JSON framing over any async byte stream.
//!
//! Each message is `[u32 big-endian length][JSON bytes]`. A hard cap on frame
//! size prevents a malicious or buggy peer from forcing an unbounded allocation.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted frame size (16 MiB) — generous for scan results, bounded
/// against abuse.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame too large: {0} bytes (max {MAX_FRAME})")]
    FrameTooLarge(u32),
    #[error("connection closed")]
    Closed,
}

/// Serialize `msg` and write it as one length-prefixed frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), CodecError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len();
    if len as u64 > MAX_FRAME as u64 {
        return Err(CodecError::FrameTooLarge(len as u32));
    }
    w.write_all(&(len as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame and deserialize it.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, CodecError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(CodecError::Closed),
        Err(e) => return Err(CodecError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(CodecError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = vec!["hello".to_string(), "world".to_string()];
        let sent = msg.clone();
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &sent).await.unwrap();
        });
        let got: Vec<String> = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn oversized_length_is_rejected() {
        // craft a frame header claiming > MAX_FRAME bytes
        let (mut a, mut b) = tokio::io::duplex(16);
        tokio::spawn(async move {
            let _ = a.write_all(&(MAX_FRAME + 1).to_be_bytes()).await;
        });
        let res: Result<serde_json::Value, _> = read_frame(&mut b).await;
        assert!(matches!(res, Err(CodecError::FrameTooLarge(_))));
    }
}
