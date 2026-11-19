use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use exposure_core::{ExposureError, Result};
use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_PAYLOAD: usize = 65000;
const MAX_NOISE_FRAME: usize = 65535;
/// Empty-payload Noise_XX_25519_ChaChaPoly_BLAKE2s handshake messages are 32, 96, and 64 bytes.
const MAX_HANDSHAKE_MSG_BYTES: usize = 256;

/// Encrypted Noise stream wrapping an arbitrary async byte stream.
/// Provides confidentiality, integrity, monotonic-nonce replay protection,
/// and exposes the Noise handshake hash `h` for upper-layer Ed25519 channel binding.
pub struct NoiseStream<S> {
    inner: S,
    state: TransportState,
    handshake_hash: Vec<u8>,
    // Read side
    read_len_buf: [u8; 2],
    read_len_pos: usize,
    read_cipher_buf: Vec<u8>,
    read_cipher_pos: usize,
    read_cipher_target: usize,
    read_plain_scratch: Vec<u8>,
    read_plain: BytesMut,
    // Write side
    write_scratch: Vec<u8>,
    write_cipher: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseStream<S> {
    pub async fn handshake_initiator(mut inner: S) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let kp = builder
            .generate_keypair()
            .map_err(|e| ExposureError::Crypto(format!("noise keypair: {e}")))?;
        let mut hs = builder
            .local_private_key(&kp.private)
            .build_initiator()
            .map_err(|e| ExposureError::Crypto(format!("noise initiator: {e}")))?;

        let mut buf = [0u8; MAX_HANDSHAKE_MSG_BYTES];

        // -> e
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg1 write: {e}")))?;
        write_hs_frame(&mut inner, &buf[..n]).await?;

        // <- e, ee, s, es
        let msg2 = read_hs_frame(&mut inner).await?;
        hs.read_message(&msg2, &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg2 read: {e}")))?;

        // -> s, se
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg3 write: {e}")))?;
        write_hs_frame(&mut inner, &buf[..n]).await?;

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let state = hs
            .into_transport_mode()
            .map_err(|e| ExposureError::Crypto(format!("noise transport mode: {e}")))?;
        Ok(Self::from_state(inner, state, handshake_hash))
    }

    pub async fn handshake_responder(mut inner: S) -> Result<Self> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let kp = builder
            .generate_keypair()
            .map_err(|e| ExposureError::Crypto(format!("noise keypair: {e}")))?;
        let mut hs = builder
            .local_private_key(&kp.private)
            .build_responder()
            .map_err(|e| ExposureError::Crypto(format!("noise responder: {e}")))?;

        let mut buf = [0u8; MAX_HANDSHAKE_MSG_BYTES];

        // <- e
        let msg1 = read_hs_frame(&mut inner).await?;
        hs.read_message(&msg1, &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg1 read: {e}")))?;

        // -> e, ee, s, es
        let n = hs
            .write_message(&[], &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg2 write: {e}")))?;
        write_hs_frame(&mut inner, &buf[..n]).await?;

        // <- s, se
        let msg3 = read_hs_frame(&mut inner).await?;
        hs.read_message(&msg3, &mut buf)
            .map_err(|e| ExposureError::Crypto(format!("noise msg3 read: {e}")))?;

        let handshake_hash = hs.get_handshake_hash().to_vec();
        let state = hs
            .into_transport_mode()
            .map_err(|e| ExposureError::Crypto(format!("noise transport mode: {e}")))?;
        Ok(Self::from_state(inner, state, handshake_hash))
    }

    fn from_state(inner: S, state: TransportState, handshake_hash: Vec<u8>) -> Self {
        Self {
            inner,
            state,
            handshake_hash,
            read_len_buf: [0u8; 2],
            read_len_pos: 0,
            read_cipher_buf: vec![0u8; MAX_NOISE_FRAME],
            read_cipher_pos: 0,
            read_cipher_target: 0,
            read_plain_scratch: vec![0u8; MAX_NOISE_FRAME],
            read_plain: BytesMut::new(),
            write_scratch: vec![0u8; MAX_NOISE_FRAME],
            write_cipher: BytesMut::new(),
        }
    }

    /// Unique 32-byte Noise handshake hash `h` binding this transport session to both ephemeral keys.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }
}

async fn write_hs_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    w.write_u16(payload.len() as u16).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

async fn read_hs_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    if len == 0 || len > MAX_HANDSHAKE_MSG_BYTES {
        return Err(ExposureError::Protocol(format!(
            "invalid noise handshake frame length: {len}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

impl<S: AsyncRead + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        if !this.read_plain.is_empty() {
            let take = this.read_plain.len().min(buf.remaining());
            buf.put_slice(&this.read_plain.split_to(take));
            return Poll::Ready(Ok(()));
        }

        if this.read_cipher_target == 0 {
            while this.read_len_pos < 2 {
                let mut rb = ReadBuf::new(&mut this.read_len_buf[this.read_len_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            if this.read_len_pos == 0 {
                                return Poll::Ready(Ok(())); // clean EOF
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated noise frame length",
                            )));
                        }
                        this.read_len_pos += n;
                    }
                }
            }
            let frame_len = u16::from_be_bytes(this.read_len_buf) as usize;
            this.read_len_pos = 0;
            if frame_len == 0 || frame_len > MAX_NOISE_FRAME {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid noise frame length: {frame_len}"),
                )));
            }
            this.read_cipher_target = frame_len;
            this.read_cipher_pos = 0;
        }

        while this.read_cipher_pos < this.read_cipher_target {
            let target = this.read_cipher_target;
            let mut rb = ReadBuf::new(&mut this.read_cipher_buf[this.read_cipher_pos..target]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated noise frame payload",
                        )));
                    }
                    this.read_cipher_pos += n;
                }
            }
        }

        let cipher_len = this.read_cipher_target;
        this.read_cipher_target = 0;
        this.read_cipher_pos = 0;

        let plain_len = this
            .state
            .read_message(
                &this.read_cipher_buf[..cipher_len],
                &mut this.read_plain_scratch[..cipher_len],
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("noise decrypt failed: {e}"))
            })?;

        if plain_len == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty noise transport frame rejected",
            )));
        }

        let take = plain_len.min(buf.remaining());
        buf.put_slice(&this.read_plain_scratch[..take]);
        if take < plain_len {
            this.read_plain
                .extend_from_slice(&this.read_plain_scratch[take..plain_len]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        while !this.write_cipher.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_cipher) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero on noise transport",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_cipher.advance(n);
                }
            }
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = data.len().min(MAX_NOISE_PAYLOAD);
        let enc_len = this
            .state
            .write_message(&data[..chunk_len], &mut this.write_scratch)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("noise encrypt: {e}")))?;

        this.write_cipher.reserve(2 + enc_len);
        this.write_cipher
            .extend_from_slice(&(enc_len as u16).to_be_bytes());
        this.write_cipher
            .extend_from_slice(&this.write_scratch[..enc_len]);

        while !this.write_cipher.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_cipher) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero on noise transport",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_cipher.advance(n),
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.write_cipher.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_cipher) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero on noise flush",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_cipher.advance(n),
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
