use std::io;

use http::{Request, HeaderMap, HeaderValue, Response};
use h2::{
    client::{self, SendRequest},
    RecvStream,
};
use tokio::{net::TcpStream, task};
use thiserror::Error;
use bytes::Bytes;

use super::jwt;

pub use jwt_simple::Error as JwtError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    H2(#[from] h2::Error),
    #[error("{0}")]
    Http(#[from] http::Error),
}

#[derive(Clone)]
pub struct Config {
    pub sandbox: bool,
    pub es256_secret: [u8; 32],
    pub key_id: String,
    pub issuer: String,
    pub bundle_id: String,
}

struct Connection {
    inner: SendRequest<Bytes>,
    handle: task::JoinHandle<()>,
}

pub struct Client {
    config: Config,
    token: jwt::T,
    connector: tokio_rustls::TlsConnector,
    connection: Option<Connection>,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, JwtError> {
        let token = jwt::T::new(&config.es256_secret, &config.key_id)?;
        Ok(Client {
            config,
            token,
            connector: h2_connector(),
            connection: None,
        })
    }

    fn endpoint(&self) -> &str {
        if self.config.sandbox {
            "api.sandbox.push.apple.com"
        } else {
            "api.push.apple.com"
        }
    }

    async fn new_connection(&self) -> Result<Connection, Error> {
        let tcp = TcpStream::connect((self.endpoint(), 443)).await?;
        let tls = self
            .connector
            .connect(self.endpoint().try_into().unwrap(), tcp)
            .await?;
        let (inner, connection) = client::handshake(tls).await?;
        let handle = tokio::spawn(async move {
            if let Err(err) = connection.await {
                log::error!("{err}");
            }
        });

        Ok(Connection { inner, handle })
    }

    /// hint: use `None.into_iter().collect()` as empty additional headers
    pub async fn send_request(
        &mut self,
        device_token: [u8; 32],
        payload: &str,
        additional_headers: HeaderMap<HeaderValue>,
    ) -> Result<Response<RecvStream>, Error> {
        if self.connection.is_none() {
            self.connection = Some(self.new_connection().await?);
        }

        self.send_request_inner(device_token, payload, additional_headers)
            .await
            .map_err(|err| {
                if let Some(Connection { handle, .. }) = self.connection.take() {
                    if !handle.is_finished() {
                        handle.abort();
                    }
                }
                err
            })
    }

    async fn send_request_inner(
        &mut self,
        device_token: [u8; 32],
        payload: &str,
        additional_headers: HeaderMap<HeaderValue>,
    ) -> Result<Response<RecvStream>, Error> {
        let auth = self.token.regenerate(&self.config.issuer);
        let request = {
            let device_token = hex::encode(device_token);
            let uri = format!("https://{}/3/device/{device_token}", self.endpoint());
            let mut request = Request::post(uri).body(())?;
            let mut headers = additional_headers;
            headers.insert("authorization", format!("bearer {auth}").parse().unwrap());
            headers.insert("apns-topic", self.config.bundle_id.parse().unwrap());
            *request.headers_mut() = headers;
            request
        };
        let payload = format!("{{ \"aps\": {payload} }}");

        let connection = self.connection.as_mut().unwrap();
        let (response, mut stream) = connection.inner.send_request(request, false)?;
        stream.send_data(payload.into(), true)?;

        response.await.map_err(From::from)
    }
}

fn h2_connector() -> tokio_rustls::TlsConnector {
    use std::sync::Arc;
    use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

    let tls_client_config = Arc::new({
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut c = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        c.alpn_protocols.push(b"h2".as_ref().to_owned());
        c
    });

    tls_client_config.into()
}
