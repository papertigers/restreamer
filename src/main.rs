mod config;

use anyhow::bail;
use bytes::{Bytes, BytesMut};
use config::{Config, Server};
use dropshot::{
    endpoint, ApiDescription, Body, ClientErrorStatusCode, ConfigDropshot,
    ConfigLogging, ConfigLoggingLevel, HandlerTaskMode::CancelOnDisconnect,
    HttpError, HttpResponseOk, Query, RequestContext, ServerBuilder,
};
use futures_util::future;
use http_body_util::StreamBody;
use hyper::{body::Frame, Response};
use illumos_priv::{PrivOp, PrivPtype, PrivSet, Privilege};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, info};
use std::{
    io::SeekFrom,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::Duration,
};
use structopt::StructOpt;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, BufReader},
    sync::{
        mpsc::{self, Sender},
        RwLock,
    },
};
use tokio_stream::wrappers::ReceiverStream;

const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Debug, StructOpt)]
#[structopt(name = PROGRAM_NAME, about = "restream Channels DVR")]
struct Opt {
    #[structopt(
        parse(from_os_str),
        short = "c",
        long = "config",
        required = true
    )]
    config_path: PathBuf,
}

struct StreamTracker(Arc<()>);
// The `()` is used to tracking connected clients even though it's never used
#[allow(dead_code)]
struct StreamTrackerPermit(Weak<()>);

impl StreamTracker {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn permit(&self) -> StreamTrackerPermit {
        StreamTrackerPermit(Arc::downgrade(&self.0))
    }

    fn active_permits(&self) -> usize {
        Arc::weak_count(&self.0)
    }
}

type AppCtx = Arc<App>;
struct App {
    pub watch_dir: PathBuf,
    pub scan_interval: u64,
    pub dvr_file: RwLock<Option<PathBuf>>,
    pub enabled: AtomicBool,
    users: Vec<config::User>,
    tracker: StreamTracker,
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
                ClientErrorStatusCode::UNAUTHORIZED,
                "Provide a valid auth token".into(),
            )
        })
    }

    fn require_admin_auth<T: AsRef<str>>(
        &self,
        token: T,
    ) -> Result<&config::User, HttpError> {
        let user = self.require_auth(token)?;
        match user.is_admin() {
            true => Ok(user),
            false => Err(HttpError::for_client_error(
                None,
                ClientErrorStatusCode::UNAUTHORIZED,
                "Insufficient creds".into(),
            )),
        }
    }
}

async fn stream_to_body<P: AsRef<Path>>(
    path: P,
    _permit: StreamTrackerPermit,
    body: Sender<Result<Frame<Bytes>, HttpError>>,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let mut buf = vec![0; 1024];
    let mut file = BufReader::new(File::open(path).await?);
    let mut counter = 0;

    // Read the mpg headers and send them
    file.read_exact(&mut buf).await?;
    body.send(Ok(Frame::data(buf.into()))).await?;

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
            counter += 1;
            // in the case where the file stops growing, we end up sleeping for
            // 10ms at a time. So, size the range to roughly 5s of inactivity.
            if counter > 500 {
                // EOF
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }

        // reset counter so that we don't prematurely end a stream.
        counter = 0;

        // TODO a DTrace probe here would be nice so we could see the avg byte
        // size we have read and are attempting to send.
        body.send(Ok(Frame::data(buf.freeze()))).await?;
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

            let new_last_modified = ent.metadata().await?.modified()?;
            let new_file = ent.path();

            match (&file, last_modified) {
                (None, None) => {
                    file = Some(ent.path());
                    last_modified = Some(new_last_modified);
                    needs_update = true;
                }
                (Some(old_file), Some(old_last_modified)) => {
                    if new_last_modified > old_last_modified {
                        if old_file != &new_file {
                            needs_update = true;
                        }
                        file = Some(new_file);
                        last_modified = Some(new_last_modified);
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

        tokio::time::sleep(Duration::from_secs(app.scan_interval)).await;
    }
}

#[derive(Deserialize, JsonSchema)]
struct AuthQueryParam {
    auth: String,
}

#[derive(Deserialize, JsonSchema)]
struct EnableStreamQueryParam {
    enabled: bool,
}

#[endpoint {
    method = PUT,
    path = "/api/live"
}]
/// Admin endpoint to enable/disable the servers live stream.
async fn enable_live_stream(
    rqctx: RequestContext<AppCtx>,
    query_parms: Query<EnableStreamQueryParam>,
    auth_parms: Query<AuthQueryParam>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let app = rqctx.context();
    let query = query_parms.into_inner();
    let auth = auth_parms.into_inner();
    app.require_admin_auth(auth.auth)?;

    // TODO we could also check for existing live streams and use a notify
    // channel to shutdown them down if an admin has disabled live streaming.
    app.enabled.store(query.enabled, Ordering::SeqCst);
    Ok(HttpResponseOk(()))
}

#[derive(Serialize, JsonSchema)]
struct StatusResponse {
    /// Number of active streams
    active: usize,
    /// Directory being watched
    watch_dir: PathBuf,
    /// Current file to stream
    file: Option<String>,
    /// Streaming enabled
    enabled: bool,
}

#[endpoint {
    method = GET,
    path = "/api/status"
}]
/// Admin endpoint to get server status.
async fn get_status(
    rqctx: RequestContext<AppCtx>,
    auth_parms: Query<AuthQueryParam>,
) -> Result<HttpResponseOk<StatusResponse>, HttpError> {
    let app = rqctx.context();
    let auth = auth_parms.into_inner();
    app.require_admin_auth(auth.auth)?;

    let file =
        app.dvr_file.read().await.clone().and_then(|p| {
            p.file_name().map(|f| f.to_string_lossy().into_owned())
        });

    let resp = StatusResponse {
        active: app.tracker.active_permits(),
        watch_dir: app.watch_dir.clone(),
        file,
        enabled: app.enabled.load(Ordering::SeqCst),
    };

    Ok(HttpResponseOk(resp))
}

#[endpoint {
    method = GET,
    path = "/live"
}]
/// Live stream endpoint for end users.
async fn live_stream(
    rqctx: RequestContext<AppCtx>,
    auth_parms: Query<AuthQueryParam>,
) -> Result<Response<Body>, HttpError> {
    let app = rqctx.context();
    let auth = auth_parms.into_inner();
    let _user = app.require_auth(auth.auth)?;

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
    let (tx, rx) = mpsc::channel::<Result<Frame<_>, _>>(10);
    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream);
    let permit = app.tracker.permit();
    let log = rqctx.log.clone();
    tokio::spawn(async move {
        match stream_to_body(file, permit, tx).await {
            Ok(_) => info!(log, "reached EOF for live stream"),
            Err(e) => error!(log, "stream error: {e:?}"),
        }
    });

    Ok(Response::new(Body::wrap(body)))
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

fn main() -> anyhow::Result<()> {
    let opts = Opt::from_args();

    let log = ConfigLogging::StderrTerminal { level: ConfigLoggingLevel::Info }
        .to_logger(PROGRAM_NAME)?;

    let Config {
        server:
            Server {
                host,
                port,
                reduce_privs,
                watch_dir,
                threads,
                scan_interval,
                default_enabled,
            },
        users,
        tls,
    } = Config::from_file(opts.config_path)?;

    if let Some(true) = reduce_privs {
        drop_privs()?;
    }

    let nthreads = threads.unwrap_or(4);
    let scan_interval = scan_interval.unwrap_or(60 * 5);
    let tls = tls.map(From::from);
    let enabled = default_enabled.unwrap_or(false);

    let mut api = ApiDescription::new();
    api.register(live_stream).unwrap();
    api.register(enable_live_stream).unwrap();
    api.register(get_status).unwrap();

    let app = Arc::new(App {
        watch_dir,
        scan_interval,
        dvr_file: RwLock::new(None),
        enabled: AtomicBool::new(enabled),
        users,
        tracker: StreamTracker::new(),
    });
    let app_clone = Arc::clone(&app);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(nthreads)
        .thread_name(format!("{}-worker", PROGRAM_NAME))
        .enable_io()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime");

    if let Err(e) = rt.block_on(async {
        let server_config = ConfigDropshot {
            bind_address: SocketAddr::new(host, port),
            default_request_body_max_bytes: 1024,
            default_handler_task_mode: CancelOnDisconnect,
            log_headers: Vec::new(),
        };

        let watcher = async {
            find_latest_file(app_clone).await.map_err(|e| format!("{e}"))
        };
        let server = ServerBuilder::new(api, app, log)
            .config(server_config)
            .tls(tls)
            .start()
            .map_err(|e| format!("failed to create server: {}", e))?;

        future::try_join(server, watcher).await
    }) {
        bail! {"{e}"};
    };

    Ok(())
}
