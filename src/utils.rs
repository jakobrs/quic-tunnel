use std::{
    path::Path,
    pin::Pin,
    task::{self, Poll},
};

use rustls::{Certificate, PrivateKey};
use tokio::io::{AsyncRead, AsyncWrite};

pub fn read_certs(file: &Path) -> std::io::Result<Vec<Certificate>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    let certs = rustls_pemfile::certs(&mut file_reader)?;

    Ok(certs.into_iter().map(Certificate).collect())
}

pub fn read_key(file: &Path) -> std::io::Result<Option<PrivateKey>> {
    let mut file_reader = std::io::BufReader::new(std::fs::File::open(file)?);

    for item in rustls_pemfile::read_all(&mut file_reader)? {
        match item {
            rustls_pemfile::Item::X509Certificate(_) => {
                log::info!("Found certificate in file meant for private key, skipping")
            }
            rustls_pemfile::Item::RSAKey(key) => return Ok(Some(PrivateKey(key))),
            rustls_pemfile::Item::PKCS8Key(key) => return Ok(Some(PrivateKey(key))),
            rustls_pemfile::Item::ECKey(key) => return Ok(Some(PrivateKey(key))),
            _ => log::info!("Unrecognised PEM item"),
        }
    }

    Ok(None)
}

pub struct QuinnBiStream {
    pub send_stream: quinn::SendStream,
    pub recv_stream: quinn::RecvStream,
}

impl AsyncRead for QuinnBiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnBiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().send_stream).poll_shutdown(cx)
    }
}
