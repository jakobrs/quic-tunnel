use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use futures_util::{FutureExt, Stream, StreamExt, TryFutureExt};
use hyper::{
    client::HttpConnector,
    server::accept::Accept,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, StatusCode,
};
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::RootCertStore;
use tokio::net::TcpStream;

use quic_tunnel::utils::{self, QuinnBiStream};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    cert: PathBuf,

    #[clap(long)]
    key: PathBuf,

    #[clap(long)]
    client_ca: PathBuf,

    #[clap(long)]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opts = Opts::from_args();

    let cert = utils::read_certs(Path::new(&opts.cert))?;
    let key = utils::read_key(Path::new(&opts.key))?.unwrap();

    let ca = utils::read_certs(Path::new(&opts.client_ca))?;
    let mut roots = RootCertStore::empty();
    for cert in ca {
        roots.add(&cert)?;
    }

    let client = Client::builder()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .build_http();

    let rustls_server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(rustls::server::AllowAnyAuthenticatedClient::new(roots))
        .with_single_cert(cert, key)?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(rustls_server_config));
    let mut transport_config = TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    server_config.transport = Arc::new(transport_config);

    let (endpoint, incoming) = Endpoint::server(server_config, opts.listen_addr)?;
    log::info!("Listening on {}", endpoint.local_addr()?);

    let incoming = Acceptor::new(incoming);

    let make_service = make_service_fn(|_socket: &QuinnBiStream| {
        let client = client.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| tunnel(req, client.clone()))) }
    });

    hyper::server::Server::builder(incoming)
        .http1_only(true)
        .serve(make_service)
        .await?;

    Ok(())
}

struct Acceptor {
    inner: Pin<Box<dyn Stream<Item = QuinnBiStream> + Send>>,
}

impl Acceptor {
    fn new(incoming: quinn::Incoming) -> Self {
        let flattened_incoming_stream = incoming.flat_map_unordered(None, |a| {
            a.map(|b| b.map(|c| c.bi_streams))
                .try_flatten_stream()
                .take_while(|d| {
                    futures_util::future::ready({
                        let err = d.as_ref().err().cloned();

                        if let Some(err) = err {
                            log::error!("Connection error: {err}");
                            false
                        } else {
                            true
                        }
                    })
                })
                .map(|d| match d {
                    Ok((send_stream, recv_stream)) => QuinnBiStream {
                        send_stream,
                        recv_stream,
                    },
                    Err(_e) => unreachable!(),
                })
        });

        Self {
            inner: flattened_incoming_stream.boxed(),
        }
    }
}

impl Accept for Acceptor {
    type Conn = QuinnBiStream;

    type Error = Infallible;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        self.get_mut().inner.poll_next_unpin(cx).map(|c| c.map(Ok))
    }
}

async fn tunnel(
    req: Request<Body>,
    client: Client<HttpConnector>,
) -> Result<Response<Body>, hyper::Error> {
    if let Some(authority) = req.uri().authority() {
        let authority = authority.to_string();

        if req.method() == Method::CONNECT {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(err) = tunnel_proxy(upgraded, authority).await {
                            log::error!("Error in tunnel_proxy: {err:?}");
                        }
                    }
                    Err(err) => log::error!("Error: {err:?}"),
                }
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        } else {
            client.request(req).await
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::empty())
            .unwrap())
    }
}

async fn tunnel_proxy(mut upgraded: Upgraded, remote: String) -> Result<(), std::io::Error> {
    let mut remote = TcpStream::connect(remote).await?;

    let stats = tokio::io::copy_bidirectional(&mut upgraded, &mut remote).await?;
    log::info!("Stats: {stats:?}");

    Ok(())
}
