use std::net::SocketAddr;
use std::pin::Pin;

use async_trait::async_trait;
use exposure_core::{ExposureError, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> TransportStream for T {}

pub type BoxedStream = Pin<Box<dyn TransportStream>>;

#[async_trait]
pub trait TransportListener: Send + Sync {
    async fn accept(&self) -> Result<(BoxedStream, SocketAddr)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

/// Extensible transport abstraction (TCP by default; ready for QUIC/UDP/etc.).
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, addr: &str) -> Result<BoxedStream>;
    async fn bind(&self, addr: &str) -> Result<Box<dyn TransportListener>>;
}

#[derive(Debug, Default, Clone)]
pub struct TcpTransport;

struct TcpTransportListener {
    inner: TcpListener,
}

#[async_trait]
impl TransportListener for TcpTransportListener {
    async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        let _ = stream.set_nodelay(true);
        Ok((Box::pin(stream), addr))
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, addr: &str) -> Result<BoxedStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ExposureError::Link(format!("tcp connect {addr}: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::pin(stream))
    }

    async fn bind(&self, addr: &str) -> Result<Box<dyn TransportListener>> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ExposureError::Link(format!("tcp bind {addr}: {e}")))?;
        Ok(Box::new(TcpTransportListener { inner: listener }))
    }
}
