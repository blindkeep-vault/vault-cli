use nix::libc;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vault_core::crypto::MasterKey;

// --- Protocol types ---

const MAX_MSG_SIZE: u32 = 65536;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Ping,
    Store {
        jwt: String,
        master_key: String,
        api_url: String,
        user_id: String,
    },
    Retrieve,
    Lock,
}

#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    master_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Response {
    fn ok() -> Self {
        Self {
            ok: true,
            pid: None,
            jwt: None,
            master_key: None,
            api_url: None,
            user_id: None,
            reason: None,
        }
    }

    fn error(reason: &str) -> Self {
        Self {
            ok: false,
            reason: Some(reason.to_string()),
            pid: None,
            jwt: None,
            master_key: None,
            api_url: None,
            user_id: None,
        }
    }
}

// --- Wire protocol: 4-byte BE length + JSON ---

fn write_message(stream: &mut UnixStream, msg: &[u8]) -> std::io::Result<()> {
    let len = msg.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(msg)?;
    stream.flush()
}

fn read_message(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// --- Paths ---

fn agent_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("blindkeep")
    } else {
        let uid = nix::unistd::getuid();
        PathBuf::from(format!("/tmp/blindkeep-{}", uid))
    }
}

pub fn socket_path() -> PathBuf {
    agent_dir().join("agent.sock")
}

fn pid_path() -> PathBuf {
    agent_dir().join("agent.pid")
}

fn ensure_agent_dir() {
    let dir = agent_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
            eprintln!("error creating agent directory: {}", e);
            std::process::exit(1);
        });
    }
    #[cfg(unix)]
    {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap_or_else(
            |e| {
                eprintln!("error setting directory permissions: {}", e);
                std::process::exit(1);
            },
        );
    }
}

// --- Agent state ---

struct CachedAuth {
    jwt: String,
    master_key: MasterKey,
    api_url: String,
    user_id: String,
}

struct AgentState {
    cached: Option<CachedAuth>,
    last_access: Instant,
    timeout: Duration,
}

impl AgentState {
    fn new(timeout_mins: u64) -> Self {
        Self {
            cached: None,
            last_access: Instant::now(),
            timeout: Duration::from_secs(timeout_mins * 60),
        }
    }

    fn touch(&mut self) {
        self.last_access = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.cached.is_some() && self.last_access.elapsed() > self.timeout
    }

    fn lock(&mut self) {
        // MasterKey implements Zeroize on drop
        self.cached = None;
    }
}

// --- Connection handler ---

fn handle_connection(mut stream: UnixStream, state: &Arc<Mutex<AgentState>>) {
    // Verify peer credentials (Linux)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let cred: libc::ucred = unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ret = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if ret != 0 {
                return;
            }
            cred
        };
        let my_uid = nix::unistd::getuid().as_raw();
        if cred.uid != my_uid {
            return;
        }
    }

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let msg = match read_message(&mut stream) {
        Ok(m) => m,
        Err(_) => return,
    };

    let request: Request = match serde_json::from_slice(&msg) {
        Ok(r) => r,
        Err(_) => {
            let resp = Response::error("invalid request");
            let _ = write_message(&mut stream, &serde_json::to_vec(&resp).unwrap());
            return;
        }
    };

    let response = match request {
        Request::Ping => {
            let mut r = Response::ok();
            r.pid = Some(std::process::id());
            r
        }
        Request::Store {
            jwt,
            master_key,
            api_url,
            user_id,
        } => {
            let key_bytes = match hex::decode(&master_key) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    let _ = write_message(
                        &mut stream,
                        &serde_json::to_vec(&Response::error("invalid key")).unwrap(),
                    );
                    return;
                }
            };

            let mk = MasterKey::from_bytes(key_bytes);

            // mlock the master key in the agent state
            let mut guard = state.lock().unwrap();
            guard.cached = Some(CachedAuth {
                jwt,
                master_key: mk,
                api_url,
                user_id,
            });
            guard.touch();

            // mlock the key bytes in heap (best-effort)
            if let Some(ref cached) = guard.cached {
                let ptr = cached.master_key.as_bytes().as_ptr();
                unsafe {
                    libc::mlock(ptr as *const libc::c_void, 32);
                }
            }

            Response::ok()
        }
        Request::Retrieve => {
            let mut guard = state.lock().unwrap();
            if guard.is_expired() {
                guard.lock();
            }
            if let Some(cached) = &guard.cached {
                let resp = Response {
                    ok: true,
                    jwt: Some(cached.jwt.clone()),
                    master_key: Some(hex::encode(cached.master_key.as_bytes())),
                    api_url: Some(cached.api_url.clone()),
                    user_id: Some(cached.user_id.clone()),
                    pid: None,
                    reason: None,
                };
                guard.touch();
                resp
            } else {
                Response::error("locked")
            }
        }
        Request::Lock => {
            let mut guard = state.lock().unwrap();
            guard.lock();
            Response::ok()
        }
    };

    let _ = write_message(&mut stream, &serde_json::to_vec(&response).unwrap());
}

// --- Daemon ---

pub fn run_start(timeout_mins: u64) {
    run_start_inner(timeout_mins, false);
}

pub fn run_start_quiet(timeout_mins: u64) {
    run_start_inner(timeout_mins, true);
}

fn run_start_inner(timeout_mins: u64, quiet: bool) {
    ensure_agent_dir();

    let sock = socket_path();

    // Check if an agent is already running
    if sock.exists() {
        if let Ok(mut stream) = UnixStream::connect(&sock) {
            let ping = serde_json::to_vec(&Request::Ping).unwrap();
            if write_message(&mut stream, &ping).is_ok() {
                if let Ok(msg) = read_message(&mut stream) {
                    if let Ok(resp) = serde_json::from_slice::<Response>(&msg) {
                        if resp.ok {
                            if !quiet {
                                eprintln!("Agent already running (pid {})", resp.pid.unwrap_or(0));
                                println!(
                                    "VAULT_AGENT_SOCK={}; export VAULT_AGENT_SOCK;",
                                    sock.display()
                                );
                            }
                            return;
                        }
                    }
                }
            }
        }
        // Stale socket, remove it
        let _ = std::fs::remove_file(&sock);
    }

    // Double-fork daemonize
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            // Parent: wait for socket to appear
            for _ in 0..20 {
                if sock.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !quiet {
                println!(
                    "VAULT_AGENT_SOCK={}; export VAULT_AGENT_SOCK;",
                    sock.display()
                );
                println!("VAULT_AGENT_PID={}; export VAULT_AGENT_PID;", child);
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            // First child: create new session
            nix::unistd::setsid().ok();

            // Second fork to fully detach
            match unsafe { nix::unistd::fork() } {
                Ok(nix::unistd::ForkResult::Parent { .. }) => {
                    // Intermediate child exits
                    std::process::exit(0);
                }
                Ok(nix::unistd::ForkResult::Child) => {
                    // Grandchild: the actual daemon
                    run_daemon(sock, timeout_mins);
                }
                Err(e) => {
                    eprintln!("error: second fork failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("error: fork failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_daemon(sock: PathBuf, timeout_mins: u64) {
    // Redirect stdio to /dev/null
    let devnull = std::fs::File::open("/dev/null").unwrap();
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::dup2(devnull.as_raw_fd(), 0);
        libc::dup2(devnull.as_raw_fd(), 1);
        libc::dup2(devnull.as_raw_fd(), 2);
    }

    // Write PID file
    let pid = std::process::id();
    std::fs::write(pid_path(), pid.to_string()).ok();

    // Set up signal handling via a self-pipe
    let (sig_read, sig_write) = std::os::unix::net::UnixStream::pair().unwrap();
    sig_read.set_nonblocking(true).ok();
    sig_write.set_nonblocking(true).ok();

    // Store the write end's fd in an atomic for the signal handler
    use std::sync::atomic::{AtomicI32, Ordering};
    static SIG_FD: AtomicI32 = AtomicI32::new(-1);
    SIG_FD.store(sig_write.as_raw_fd(), Ordering::SeqCst);
    std::mem::forget(sig_write); // prevent drop so fd stays valid

    extern "C" fn handle_signal(_: libc::c_int) {
        let fd = SIG_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
        }
    }

    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
    }

    // Remove stale socket, bind new one
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap_or_else(|e| {
        eprintln!("error binding socket: {}", e);
        std::process::exit(1);
    });

    // Set socket permissions to 0600
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).ok();

    // Non-blocking so we can check signals
    listener.set_nonblocking(true).ok();

    let state = Arc::new(Mutex::new(AgentState::new(timeout_mins)));

    // TTL checker thread — on expiry, zeroize keys and signal shutdown
    let ttl_state = Arc::clone(&state);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        let mut guard = ttl_state.lock().unwrap();
        if guard.is_expired() {
            guard.lock();
            drop(guard);
            // Signal the accept loop to exit
            unsafe {
                libc::kill(std::process::id() as i32, libc::SIGTERM);
            }
            break;
        }
    });

    // Accept loop
    loop {
        // Check for shutdown signal
        let mut sig_buf = [0u8; 1];
        if sig_read.try_clone().unwrap().read(&mut sig_buf).is_ok() {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                let conn_state = Arc::clone(&state);
                std::thread::spawn(move || {
                    handle_connection(stream, &conn_state);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    // Cleanup
    {
        let mut guard = state.lock().unwrap();
        guard.lock(); // zeroize key
    }
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(pid_path());
}

pub fn run_stop() {
    let pid_file = pid_path();
    let sock = socket_path();

    // Try graceful shutdown via socket first
    if sock.exists() {
        if let Ok(mut stream) = UnixStream::connect(&sock) {
            let lock_req = serde_json::to_vec(&Request::Lock).unwrap();
            let _ = write_message(&mut stream, &lock_req);
            let _ = read_message(&mut stream);
        }
    }

    if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Send SIGTERM
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            // Wait briefly for clean shutdown
            for _ in 0..20 {
                unsafe {
                    if libc::kill(pid, 0) != 0 {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    // Clean up files
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pid_file);
    eprintln!("Agent stopped");
}

pub fn run_lock() {
    let sock = socket_path();
    match UnixStream::connect(&sock) {
        Ok(mut stream) => {
            let req = serde_json::to_vec(&Request::Lock).unwrap();
            if write_message(&mut stream, &req).is_ok() {
                if let Ok(msg) = read_message(&mut stream) {
                    if let Ok(resp) = serde_json::from_slice::<Response>(&msg) {
                        if resp.ok {
                            eprintln!("Agent locked");
                            return;
                        }
                    }
                }
            }
            eprintln!("error: failed to lock agent");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("error: no agent running");
            std::process::exit(1);
        }
    }
}

pub fn run_status() {
    let sock = socket_path();
    if !sock.exists() {
        eprintln!("Agent: not running");
        return;
    }
    match UnixStream::connect(&sock) {
        Ok(mut stream) => {
            let req = serde_json::to_vec(&Request::Ping).unwrap();
            if write_message(&mut stream, &req).is_ok() {
                if let Ok(msg) = read_message(&mut stream) {
                    if let Ok(resp) = serde_json::from_slice::<Response>(&msg) {
                        if resp.ok {
                            eprintln!("Agent: running (pid {})", resp.pid.unwrap_or(0));
                            return;
                        }
                    }
                }
            }
            eprintln!("Agent: socket exists but not responding");
        }
        Err(_) => {
            eprintln!("Agent: socket exists but not connectable (stale?)");
        }
    }
}

// --- Client helpers (used by get_auth) ---

pub fn try_retrieve() -> Option<(String, MasterKey, String, String)> {
    let sock = socket_path();
    let mut stream = UnixStream::connect(&sock).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let req = serde_json::to_vec(&Request::Retrieve).unwrap();
    write_message(&mut stream, &req).ok()?;

    let msg = read_message(&mut stream).ok()?;
    let resp: Response = serde_json::from_slice(&msg).ok()?;

    if !resp.ok {
        return None;
    }

    let jwt = resp.jwt?;
    let key_hex = resp.master_key?;
    let api_url = resp.api_url?;
    let user_id = resp.user_id?;

    let key_bytes = hex::decode(&key_hex).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    let mk = MasterKey::from_bytes(arr);

    // Zeroize the hex string on the stack (best-effort)
    // The key_bytes vec will be dropped normally

    Some((jwt, mk, api_url, user_id))
}

pub fn try_store(jwt: &str, master_key: &MasterKey, api_url: &str, user_id: &str) {
    let sock = socket_path();
    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) => return, // No agent running, silently skip
    };
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let req = Request::Store {
        jwt: jwt.to_string(),
        master_key: hex::encode(master_key.as_bytes()),
        api_url: api_url.to_string(),
        user_id: user_id.to_string(),
    };

    let msg = serde_json::to_vec(&req).unwrap();
    let _ = write_message(&mut stream, &msg);
    let _ = read_message(&mut stream);
}
