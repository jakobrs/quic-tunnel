use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::Parser;
use quic_tunnel::utils::{self, QuinnBiStream};
use quinn::{ClientConfig, Endpoint, NewConnection};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    cert: PathBuf,

    #[clap(long)]
    key: PathBuf,

    #[clap(long)]
    remote_addr: SocketAddr,

    #[clap(long)]
    server_name: String,

    #[clap(long)]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opts = Opts::from_args();

    let cert = utils::read_certs(Path::new(&opts.cert))?;
    let key = utils::read_key(Path::new(&opts.key))?.unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let rustls_client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_single_cert(cert, key)?;

    let client_config = ClientConfig::new(Arc::new(rustls_client_config));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let NewConnection {
        connection: conn, ..
    } = endpoint
        .connect(opts.remote_addr, &opts.server_name)?
        .await?;

    log::info!("Connected to proxy server");

    let listener = TcpListener::bind(opts.listen_addr).await?;

    loop {
        let (client, client_addr) = listener.accept().await?;
        log::info!("Received connection from {client_addr}");

        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(client, conn).await {
                log::error!("Error in client task: {err}");
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, conn: quinn::Connection) -> Result<()> {
    let (send_stream, recv_stream) = conn.open_bi().await?;
    let mut quinn_bi_stream = QuinnBiStream {
        send_stream,
        recv_stream,
    };

    let stats = tokio::io::copy_bidirectional(&mut client, &mut quinn_bi_stream).await?;
    log::info!("Stats: {stats:?}");

    log::info!("Closing connection with client, and stream");
    quinn_bi_stream.send_stream.finish().await?;

    return Ok(());
}
