//! A Rust program for `test/rust.zig`: the standard library's threads,
//! locks, channels, clock, files and sockets, and tokio's two runtimes.
//! Each function returns 0, or the number of the step that went wrong.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Four threads add to a counter under a mutex and report on a channel.
#[no_mangle]
pub extern "C" fn rust_threads() -> i32 {
    let counter = Arc::new(Mutex::new(0u64));
    let (tx, rx) = mpsc::channel::<u64>();
    let mut handles = Vec::new();
    for id in 0..4u64 {
        let counter = counter.clone();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let mut held = counter.lock().unwrap();
                let seen = *held;
                std::thread::yield_now();
                *held = seen + 1;
            }
            tx.send(id).unwrap();
        }));
    }
    drop(tx);
    let mut sum = 0;
    for id in rx {
        sum += id;
    }
    for h in handles {
        if h.join().is_err() {
            return 1;
        }
    }
    if sum != 6 {
        return 2;
    }
    if *counter.lock().unwrap() != 200 {
        return 3;
    }
    0
}

/// A sleep and a condition variable's timed wait pass in virtual time.
/// Returns the nanoseconds the clock moved, or a negative step number.
#[no_mangle]
pub extern "C" fn rust_time() -> i64 {
    let before = Instant::now();
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let waker = pair.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3600));
        *waker.0.lock().unwrap() = true;
        waker.1.notify_one();
    });
    let mut ready = pair.0.lock().unwrap();
    let mut timeouts = 0;
    while !*ready {
        let (guard, result) = pair.1.wait_timeout(ready, Duration::from_secs(1000)).unwrap();
        ready = guard;
        if result.timed_out() {
            timeouts += 1;
        }
    }
    drop(ready);
    if t.join().is_err() {
        return -1;
    }
    if timeouts != 3 {
        return -2;
    }
    before.elapsed().as_nanos() as i64
}

/// A file written, synced, renamed and read back; a directory listed.
#[no_mangle]
pub extern "C" fn rust_files() -> i32 {
    if std::fs::create_dir_all("data/sub").is_err() {
        return 1;
    }
    let Ok(mut f) = std::fs::File::create("data/sub/new.tmp") else { return 2 };
    if f.write_all(b"hello from rust").is_err() || f.sync_all().is_err() {
        return 3;
    }
    drop(f);
    if std::fs::rename("data/sub/new.tmp", "data/sub/kept").is_err() {
        return 4;
    }
    let Ok(dir) = std::fs::File::open("data/sub") else { return 5 };
    if dir.sync_all().is_err() {
        return 6;
    }
    let Ok(text) = std::fs::read_to_string("data/sub/kept") else { return 7 };
    if text != "hello from rust" {
        return 8;
    }
    let Ok(entries) = std::fs::read_dir("data/sub") else { return 9 };
    let names: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
    if names.len() != 1 || names[0] != "kept" {
        return 10;
    }
    match std::fs::metadata("data/sub/kept") {
        Ok(m) if m.len() == 15 && m.is_file() => 0,
        _ => 11,
    }
}

/// Reads what `rust_files` kept, after a crash. 0 when it is whole.
#[no_mangle]
pub extern "C" fn rust_files_kept() -> i32 {
    match std::fs::read_to_string("data/sub/kept") {
        Ok(text) if text == "hello from rust" => 0,
        Ok(_) => 1,
        Err(_) => 2,
    }
}

/// `try_clone` (a `dup`): one connection read by a thread and written by
/// another, and one file under two handles that share a position.
#[no_mangle]
pub extern "C" fn rust_try_clone() -> i32 {
    use std::io::{Seek, SeekFrom};
    let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:7010") else { return 1 };
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        loop {
            let n = conn.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            conn.write_all(&buf[..n]).unwrap();
        }
    });
    let Ok(mut writer) = std::net::TcpStream::connect("127.0.0.1:7010") else { return 2 };
    let Ok(mut reader) = writer.try_clone() else { return 3 };
    let read = std::thread::spawn(move || -> usize {
        let mut total = 0;
        let mut buf = [0u8; 64];
        while total < 200 {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        total
    });
    for _ in 0..5 {
        if writer.write_all(&[7u8; 40]).is_err() {
            return 4;
        }
    }
    if read.join().unwrap_or(0) != 200 {
        return 5;
    }
    // The reader's handle went with its thread; this is the last one, and
    // the server reads the end only now.
    drop(writer);
    if server.join().is_err() {
        return 6;
    }
    let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open("clone.txt") else {
        return 7;
    };
    let Ok(mut g) = f.try_clone() else { return 8 };
    if f.write_all(b"abcdef").is_err() {
        return 9;
    }
    if g.seek(SeekFrom::Start(2)).is_err() {
        return 10;
    }
    drop(g);
    let mut two = [0u8; 2];
    if f.read_exact(&mut two).is_err() || &two != b"cd" {
        return 11;
    }
    0
}

/// A blocking TCP echo: a thread serves, three threads are clients.
#[no_mangle]
pub extern "C" fn rust_tcp() -> i32 {
    let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:7000") else { return 1 };
    let served = Arc::new(AtomicU64::new(0));
    let count = served.clone();
    let server = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for _ in 0..3 {
            let (mut conn, _) = listener.accept().unwrap();
            let count = count.clone();
            workers.push(std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                loop {
                    let n = conn.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    conn.write_all(&buf[..n]).unwrap();
                    count.fetch_add(n as u64, Ordering::SeqCst);
                }
            }));
        }
        for w in workers {
            w.join().unwrap();
        }
    });
    let mut clients = Vec::new();
    for id in 0..3u8 {
        clients.push(std::thread::spawn(move || -> bool {
            let Ok(mut conn) = std::net::TcpStream::connect("127.0.0.1:7000") else { return false };
            let msg = [b'a' + id; 40];
            for _ in 0..5 {
                if conn.write_all(&msg).is_err() {
                    return false;
                }
                let mut back = [0u8; 40];
                if conn.read_exact(&mut back).is_err() || back != msg {
                    return false;
                }
            }
            true
        }));
    }
    for c in clients {
        if !c.join().unwrap_or(false) {
            return 2;
        }
    }
    if server.join().is_err() {
        return 3;
    }
    if served.load(Ordering::SeqCst) != 600 {
        return 4;
    }
    0
}

/// A `HashMap`'s keys come from `getrandom`: the order of its entries
/// follows the seed. Returns a digest of the order.
#[no_mangle]
pub extern "C" fn rust_hash_order() -> u64 {
    let t = std::thread::spawn(|| {
        let mut map = std::collections::HashMap::new();
        for i in 0..64u64 {
            map.insert(i, ());
        }
        map.keys().fold(0u64, |acc, k| acc.wrapping_mul(1099511628211).wrapping_add(*k))
    });
    t.join().unwrap_or(0)
}

/// How many threads the standard library says are worth starting.
#[no_mangle]
pub extern "C" fn rust_parallelism() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

#[cfg(feature = "tokio")]
mod with_tokio {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo(clients: u8) -> i32 {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:7100").await else { return 1 };
        let server = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..clients {
                let (mut conn, _) = listener.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        let n = conn.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        conn.write_all(&buf[..n]).await.unwrap();
                    }
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
        });
        let mut tasks = Vec::new();
        for id in 0..clients {
            tasks.push(tokio::spawn(async move {
                let Ok(mut conn) = tokio::net::TcpStream::connect("127.0.0.1:7100").await else { return false };
                let msg = [b'a' + id; 40];
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    if conn.write_all(&msg).await.is_err() {
                        return false;
                    }
                    let mut back = [0u8; 40];
                    if conn.read_exact(&mut back).await.is_err() || back != msg {
                        return false;
                    }
                }
                true
            }));
        }
        for t in tasks {
            if !t.await.unwrap_or(false) {
                return 2;
            }
        }
        // A channel between tasks, and a timeout that expires.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
        tokio::spawn(async move {
            for i in 0..10 {
                tx.send(i).await.unwrap();
            }
        });
        let mut sum = 0;
        while let Some(v) = rx.recv().await {
            sum += v;
        }
        if sum != 45 {
            return 3;
        }
        if tokio::time::timeout(Duration::from_secs(60), std::future::pending::<()>()).await.is_ok() {
            return 4;
        }
        if server.await.is_err() {
            return 5;
        }
        0
    }

    /// A seed for tokio's scheduler from this run's `getrandom` (a new
    /// thread's hash keys are drawn from it). Left to itself tokio seeds
    /// each runtime from a counter the process keeps, so the second run
    /// of a seed would not be the first. `rng_seed` needs
    /// `--cfg tokio_unstable` (`.cargo/config.toml`).
    fn seed() -> tokio::runtime::RngSeed {
        use std::hash::BuildHasher;
        let n = std::collections::hash_map::RandomState::new().hash_one(0u8);
        tokio::runtime::RngSeed::from_bytes(&n.to_le_bytes())
    }

    /// tokio's single-threaded runtime: epoll, an eventfd, timers.
    ///
    /// On a thread of its own. The standard library keeps thread-local
    /// state that is seeded once (hash keys): on the caller's thread it
    /// would outlive the run, and the next run of the same seed would
    /// differ. A new thread's is seeded from this run's `getrandom`.
    #[no_mangle]
    pub extern "C" fn rust_tokio_current() -> i32 {
        std::thread::spawn(|| {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().rng_seed(seed()).build() else { return 100 };
            rt.block_on(echo(3))
        })
        .join()
        .unwrap_or(101)
    }

    /// tokio's work-stealing runtime as most programs build it: as many
    /// workers as the machine has processors, which tokio asks for.
    /// One, under simulation.
    #[no_mangle]
    pub extern "C" fn rust_tokio_default() -> i32 {
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().rng_seed(seed()).build() else { return 100 };
            // The simulated machine has one processor. (tokio reads
            // `TOKIO_WORKER_THREADS` from the environment first.)
            if rt.metrics().num_workers() != 1 {
                return 102;
            }
            rt.block_on(echo(3))
        })
        .join()
        .unwrap_or(101)
    }

    /// tokio's work-stealing runtime with `workers` worker threads.
    #[no_mangle]
    pub extern "C" fn rust_tokio_workers(workers: usize) -> i32 {
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().rng_seed(seed()).build() else { return 100 };
            rt.block_on(echo(3))
        })
        .join()
        .unwrap_or(101)
    }
}
