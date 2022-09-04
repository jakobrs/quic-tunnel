use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
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
    incoming: quinn::Incoming,
    connecting: FuturesUnordered<quinn::Connecting>,
    streams: FuturesUnordered<
        Pin<
            Box<
                dyn Future<
                    Output = (
                        quinn::IncomingBiStreams,
                        Option<
                            Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>,
                        >,
                    ),
                >,
            >,
        >,
    >,
}

impl Acceptor {
    fn new(incoming: quinn::Incoming) -> Self {
        Self {
            incoming,
            connecting: FuturesUnordered::new(),
            streams: FuturesUnordered::new(),
        }
    }
}

impl Accept for Acceptor {
    type Conn = QuinnBiStream;

    type Error = anyhow::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let this = self.get_mut();

        while let Poll::Ready(conn) = this.incoming.poll_next_unpin(cx) {
            match conn {
                Some(conn) => {
                    log::info!("Received connection from {}", conn.remote_address());
                    this.connecting.push(conn);
                }
                None => {
                    log::error!("this.incoming: end of stream");
                    return Poll::Ready(Some(Err(anyhow::anyhow!("this.incoming: end of stream"))));
                }
            };
        }

        while let Poll::Ready(Some(conn)) = this.connecting.poll_next_unpin(cx) {
            match conn {
                Ok(mut conn) => {
                    log::info!(
                        "Established connection with {}",
                        conn.connection.remote_address()
                    );

                    this.streams.push(
                        async move {
                            let stream = conn.bi_streams.next().await;

                            (conn.bi_streams, stream)
                        }
                        .boxed(),
                    );
                }
                Err(err) => log::error!("Connection error: {err}"),
            }
        }

        while let Poll::Ready(Some((mut streamstream, conn))) = this.streams.poll_next_unpin(cx) {
            match conn {
                Some(Ok((send_stream, recv_stream))) => {
                    this.streams.push(
                        async move {
                            let stream = streamstream.next().await;

                            (streamstream, stream)
                        }
                        .boxed(),
                    );

                    log::info!("Opened stream");
                    return Poll::Ready(Some(Ok(QuinnBiStream {
                        send_stream,
                        recv_stream,
                    })));
                }

                Some(Err(err)) => log::error!("Stream open error: {err}"),
                None => todo!(),
            }
        }

        Poll::Pending
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
