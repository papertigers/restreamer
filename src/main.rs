mod config;

use anyhow::{anyhow, bail};
use bytes::BytesMut;
use config::Config;
use dropshot::{
    endpoint, ApiDescription, ConfigDropshot, ConfigLogging,
    ConfigLoggingLevel, ConfigTls, HttpError, HttpResponseOk,
    HttpServerStarter, Query, RequestContext,
};
use futures_util::future;
use hyper::{body::Sender, Body, Response, StatusCode};
use illumos_priv::{PrivOp, PrivPtype, PrivSet, Privilege};
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{io::SeekFrom, path::Path, time::Duration};
use tokio::fs;
use tokio::sync::RwLock;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, BufReader},
};

type AppCtx = Arc<App>;
struct App {
    pub watch_dir: PathBuf,
    pub dvr_file: RwLock<Option<PathBuf>>,
    pub enabled: AtomicBool,
    users: Vec<config::User>,
}

impl App {
    fn get_user<T: AsRef<str>>(&self, token: T) -> Option<&config::User> {
        let token = token.as_ref();
        self.users.iter().find(|u| u.auth_token == token)
    }

    fn require_auth<T: AsRef<str>>(
        &self,
        token: T,
    ) -> Result<&config::User, HttpError> {
        self.get_user(token).ok_or_else(|| {
            HttpError::for_client_error(
                None,
                StatusCode::UNAUTHORIZED,
                "Provide a valid auth token".into(),
            )
        })
    }
}

async fn stream_to_body<P: AsRef<Path>>(
    path: P,
    mut body: Sender,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let mut buf = vec![0; 1024];
    let mut file = BufReader::new(File::open(path).await?);

    // Read the mpg headers and send them
    file.read_exact(&mut buf).await?;
    body.send_data(buf.into()).await?;

    // Seek to "live"
    file.seek(SeekFrom::End(256)).await?;

    // Send the data
    loop {
        let mut buf = BytesMut::with_capacity(1000 * 1000);
        file.read_buf(&mut buf).await?;

        // We are at the end of the file because it stopped growing or because
        // the consumer is too quick. In either case we should delay our next
        // read attempt.
        if buf.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
            // TODO stat the file and see if the filesize is changing to
            // determine if we should kill the stream.
            continue;
        }

        // TODO a DTrace probe here would be nice so we could see the avg byte
        // size we have read and are attempting to send.
        body.send_data(buf.freeze()).await?;
    }
}

async fn find_latest_file(app: AppCtx) -> anyhow::Result<()> {
    let mut file = None;
    let mut last_modified = None;
    let mut needs_update = false;

    loop {
        let mut ents = fs::read_dir(&app.watch_dir).await?;
        while let Some(ent) = ents.next_entry().await? {
            if !ent.file_type().await?.is_file() {
                continue;
            }

            let modified = ent.metadata().await?.modified()?;

            match (&file, last_modified) {
                (None, None) => {
                    file = Some(ent.path());
                    last_modified = Some(modified);
                }
                (Some(_old_file), Some(old_last_modified)) => {
                    if modified > old_last_modified {
                        file = Some(ent.path());
                        last_modified = Some(modified);
                        needs_update = true;
                    }
                }
                _ => unreachable!(),
            };
        }

        if needs_update {
            let mut dvr_file = app.dvr_file.write().await;
            *dvr_file = file.clone();
            needs_update = false;
        }

        tokio::time::sleep(Duration::from_secs(60 * 5)).await;
    }
}

#[derive(Deserialize, JsonSchema)]
struct EnableStreamQueryParam {
    enabled: bool,
    auth: String,
}

#[endpoint {
    method = PUT,
    path = "/api/live"
}]
/// Admin endpoint to enable/disable the servers live stream.
async fn enable_live_stream(
    rqctx: Arc<RequestContext<AppCtx>>,
    query_parms: Query<EnableStreamQueryParam>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let app = rqctx.context();
    let query = query_parms.into_inner();
    let user = app.require_auth(query.auth)?;

    if !user.is_admin() {
        return Err(HttpError::for_client_error(
            None,
            StatusCode::UNAUTHORIZED,
            "Provide a valid auth token".into(),
        ));
    }

    // TODO we could also check for existing live streams and use a notify
    // channel to shutdown them down if an admin has disabled live streaming.
    app.enabled.store(query.enabled, Ordering::SeqCst);
    Ok(HttpResponseOk(()))
}

#[derive(Deserialize, JsonSchema)]
struct LiveStreamQueryParams {
    auth: String,
}

#[endpoint {
    method = GET,
    path = "/live"
}]
/// Live stream endpoint for end users.
async fn live_stream(
    rqctx: Arc<RequestContext<AppCtx>>,
    query_params: Query<LiveStreamQueryParams>,
) -> Result<Response<Body>, HttpError> {
    let app = rqctx.context();
    let query = query_params.into_inner();
    let _user = app.require_auth(query.auth)?;

    // If an admin has disabled live streaming we should bail now.
    let enabled = app.enabled.load(Ordering::SeqCst);
    if !enabled {
        return Err(HttpError::for_unavail(
            None,
            "live stream is currently disabled".into(),
        ));
    }

    // Ensure we have a file to stream before we start.
    let file = app.dvr_file.read().await.clone().ok_or_else(|| {
        HttpError::for_unavail(None, "No file to stream".into())
    })?;

    // Everything is good lets start streaming the file.
    let (tx, body) = Body::channel();
    tokio::spawn(async {
        if let Err(e) = stream_to_body(file, tx).await {
            eprintln!("stream error: {e:?}");
        }
    });

    Ok(Response::builder().status(StatusCode::OK).body(body)?)
}

fn drop_privs() -> anyhow::Result<()> {
    let mut pset = PrivSet::new_basic()?;
    pset.delset(Privilege::ProcFork)?;
    pset.delset(Privilege::ProcExec)?;
    pset.delset(Privilege::ProcInfo)?;
    pset.delset(Privilege::ProcSession)?;
    illumos_priv::setppriv(PrivOp::Set, PrivPtype::Permitted, &pset)?;
    illumos_priv::setppriv(PrivOp::Set, PrivPtype::Limit, &pset)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log = ConfigLogging::StderrTerminal { level: ConfigLoggingLevel::Info }
        .to_logger("minimal-example")?;

    let Config { users, watch_dir, tls } = Config::from_file("config.toml")?;

    let mut api = ApiDescription::new();
    api.register(live_stream).unwrap();
    api.register(enable_live_stream).unwrap();

    let app = Arc::new(App {
        watch_dir,
        dvr_file: RwLock::new(None),
        // TODO when we have auth swap this back to false
        enabled: AtomicBool::new(true),
        users,
    });

    let watcher = find_latest_file(Arc::clone(&app));

    let tls = tls.map(|c| ConfigTls { cert_file: c.cert, key_file: c.key });

    let server = match HttpServerStarter::new(
        &ConfigDropshot {
            bind_address: "0.0.0.0:9090".parse().unwrap(),
            request_body_max_bytes: 1024,
            tls,
        },
        api,
        app,
        &log,
    ) {
        Ok(server) => server,
        Err(e) => bail!(e),
    };

    drop_privs()?;

    let http = async {
        server.start().await.map_err(|e| anyhow!("server error: {e:?}"))
    };

    if let Err(e) = future::try_join(http, watcher).await {
        bail!("{e}");
    }

    Ok(())
}
