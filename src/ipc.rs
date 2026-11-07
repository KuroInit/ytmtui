//! Tiny Unix-socket bridge for external tools, mainly Quickshell's media
//! widget: it polls `ytmtui --json queue` / `now` and jumps with `ytmtui jump <i>`.
//!
//! Newline-delimited JSON: one request in, one response line out.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc::UnboundedSender};
use tokio::time::{Duration, timeout};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 32;

/// One queue row as the widget wants it: flat, with numeric seconds.
pub struct QueueRow {
    pub title: String,
    pub artist: String,
    pub album: String,
    pub duration_secs: u64,
    pub thumbnail_url: String,
}

/// Queue facts mirrored to external clients, rewritten by the app each tick.
#[derive(Default)]
pub struct IpcState {
    pub tracks: Vec<QueueRow>,
    pub current_index: i32,
    pub repeat: String,
    pub shuffle: bool,
    pub status: String,
    pub position_secs: u64,
    pub track_id: String,
}

pub type IpcHandle = Arc<RwLock<IpcState>>;

/// Commands external clients can push into the app.
#[derive(Debug)]
pub enum IpcCmd {
    Jump(usize),
    Clear,
}

fn socket_path() -> std::io::Result<PathBuf> {
    Ok(crate::auth::private_config_dir()?.join("ytmtui.sock"))
}

/// Serve the bridge until exit. If the socket already answers, another
/// ytmtui owns it.
pub async fn serve(state: IpcHandle, tx: UnboundedSender<IpcCmd>) {
    let Ok(path) = socket_path() else { return };
    if UnixStream::connect(&path).await.is_ok() {
        return; // another instance is already bridging
    }
    let _ = std::fs::remove_file(&path); // stale socket from a dead run
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(_) => return,
    };
    // The socket lives inside a user-only directory; also narrow its mode.
    use std::os::unix::fs::PermissionsExt;
    if std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).is_err() {
        let _ = std::fs::remove_file(&path);
        return;
    }

    let clients = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = clients.clone().try_acquire_owned() else {
                    continue;
                };
                let state = state.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle(stream, &state, &tx).await;
                });
            }
            Err(_) => continue,
        }
    }
}

async fn handle(
    stream: UnixStream,
    state: &IpcHandle,
    tx: &UnboundedSender<IpcCmd>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let reader = BufReader::new(read);
    let mut line = String::new();
    // Bound both allocation and how long a client can occupy a connection slot.
    let mut limited = reader.take((MAX_REQUEST_BYTES + 1) as u64);
    let bytes = match timeout(Duration::from_secs(5), limited.read_line(&mut line)).await {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    let response = if bytes > MAX_REQUEST_BYTES {
        err("request too large")
    } else {
        route(line.trim(), state, tx)
    };
    write.write_all(response.as_bytes()).await?;
    write.write_all(b"\n").await?;
    write.shutdown().await?;
    Ok(())
}

fn route(line: &str, state: &IpcHandle, tx: &UnboundedSender<IpcCmd>) -> String {
    let Ok(req) = serde_json::from_str::<serde_json::Value>(line) else {
        return err("malformed request");
    };
    let command = req.get("command").and_then(|c| c.as_str()).unwrap_or("");
    let args = req.get("args");

    let guard = state.read().unwrap();
    match command {
        // Queue poll: { tracks, current_index, repeat, shuffle }.
        "queue" => {
            let tracks: Vec<serde_json::Value> = guard
                .tracks
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "title": t.title,
                        "artist": t.artist,
                        "album": t.album,
                        "duration": t.duration_secs,
                        "thumbnail_url": t.thumbnail_url,
                    })
                })
                .collect();
            ok(serde_json::json!({
                "tracks": tracks,
                "current_index": guard.current_index,
                "length": tracks.len(),
                "repeat": guard.repeat,
                "shuffle": guard.shuffle,
            }))
        }
        // Now-playing poll (drives the like chip only).
        "now" => ok(serde_json::json!({
            "track": {
                "title": "",
                "artist": "",
                "likeStatus": "INDIFFERENT",
            },
            "position": guard.position_secs,
            "status": guard.status,
            "video_id": guard.track_id,
        })),
        "jump" => {
            let index = args
                .and_then(|a| a.get("index"))
                .and_then(|i| i.as_u64())
                .map(|i| i as usize);
            match index {
                Some(i) if i < guard.tracks.len() => {
                    drop(guard);
                    let _ = tx.send(IpcCmd::Jump(i));
                    ok(serde_json::Value::Null)
                }
                Some(_) => err("index out of range"),
                None => err("missing index"),
            }
        }
        "queue_clear" => {
            drop(guard);
            let _ = tx.send(IpcCmd::Clear);
            ok(serde_json::Value::Null)
        }
        _ => err(&format!("unknown command: {command}")),
    }
}

fn ok(data: serde_json::Value) -> String {
    serde_json::json!({"ok": true, "data": data}).to_string()
}

fn err(message: &str) -> String {
    serde_json::json!({"ok": false, "error": message}).to_string()
}

// ---------------------------------------------------------------------------
// Client side — used by the `ytmtui queue` / `ytmtui jump` CLI.
// ---------------------------------------------------------------------------

/// Send a command to the running TUI. Blocking on purpose: the CLI runs
/// outside the async runtime.
pub fn request(command: &str, args: Option<serde_json::Value>) -> anyhow::Result<serde_json::Value> {
    use std::io::{BufRead, Write};
    let stream = std::os::unix::net::UnixStream::connect(socket_path()?)?;
    let payload = serde_json::json!({"command": command, "args": args});
    let mut stream = stream;
    stream.write_all(payload.to_string().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(test)]
mod tests {
    use super::{IpcCmd, IpcState, MAX_REQUEST_BYTES, handle};
    use std::sync::{Arc, RwLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn oversized_request_is_rejected_without_parsing_it() {
        let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
        let state = Arc::new(RwLock::new(IpcState::default()));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<IpcCmd>();
        let task = tokio::spawn(async move { handle(server, &state, &tx).await });
        client
            .write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&response).contains("request too large"));
    }
}
