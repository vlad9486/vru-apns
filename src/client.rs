use std::{
    io,
    sync::{Arc, Mutex},
    borrow::Cow,
};

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
    pub key_id: Cow<'static, str>,
    pub issuer: Cow<'static, str>,
    pub bundle_id: Cow<'static, str>,
}

pub struct Client {
    sandbox: bool,
    issuer: Cow<'static, str>,
    bundle_id: Cow<'static, str>,
    token: Arc<Mutex<jwt::T>>,
    connector: tokio_rustls::TlsConnector,
    // TODO: connection pool?
    connection: Arc<Mutex<Option<Connection>>>,
}

struct Connection {
    inner: SendRequest<Bytes>,
    task: Option<task::JoinHandle<Result<(), h2::Error>>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        tokio::spawn(self.task.take().expect("must not call drop twice"));
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            sandbox: self.sandbox,
            issuer: self.issuer.clone(),
            bundle_id: self.bundle_id.clone(),
            token: self.token.clone(),
            connector: self.connector.clone(),
            connection: Arc::new(Mutex::new(None)),
        }
    }
}

impl Client {
    pub fn new(config: Config) -> Result<Self, JwtError> {
        let token = jwt::T::new(&config.es256_secret, &config.key_id)?;
        let token = Arc::new(Mutex::new(token));
        Ok(Client {
            sandbox: config.sandbox,
            issuer: config.issuer,
            bundle_id: config.bundle_id,
            token,
            connector: h2_connector(),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    fn endpoint(&self) -> &str {
        if self.sandbox {
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
        let task = Some(tokio::spawn(connection));

        Ok(Connection { inner, task })
    }

    /// hint: use `None.into_iter().collect()` as empty additional headers
    pub async fn send_request(
        &self,
        device_token: &[u8],
        payload: String,
        additional_headers: HeaderMap<HeaderValue>,
    ) -> Result<Response<RecvStream>, Error> {
        let auth = self.token.lock().unwrap().regenerate(&self.issuer);
        let request = {
            let device_token = hex::encode(device_token);
            let uri = format!("https://{}/3/device/{device_token}", self.endpoint());
            let mut request = Request::post(uri).body(())?;
            let mut headers = additional_headers;
            headers.insert("authorization", format!("bearer {auth}").parse().unwrap());
            headers.insert("apns-topic", self.bundle_id.parse().unwrap());
            *request.headers_mut() = headers;
            request
        };

        let v = self.connection.lock().expect("poisoned").take();
        let mut connection = match v {
            Some(v) => v,
            None => self.new_connection().await?,
        };

        let (response, mut stream) = connection.inner.send_request(request, false)?;
        stream.send_data(payload.into(), true)?;
        let response = response.await?;

        *self.connection.lock().expect("poisoned") = Some(connection);

        Ok(response)
    }
}

fn h2_connector() -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

    let tls_client_config = Arc::new({
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
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
