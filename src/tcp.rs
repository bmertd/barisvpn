use crate::parse::Item;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

/// Host basina minimum aralik uygulayan throttle.
/// Amac: ayni sunucuyu bombardimana tutmayip rate-limit'e dusurmemek.
#[derive(Debug, Default)]
pub struct HostThrottle {
    last: Mutex<HashMap<String, Instant>>,
    gap: std::sync::Mutex<u64>,
}

impl HostThrottle {
    pub fn new(gap_ms: u64) -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
            gap: std::sync::Mutex::new(gap_ms),
        }
    }

    pub async fn gate(&self, host: &str) {
        let gap = *self.gap.lock().unwrap();
        if gap == 0 {
            return;
        }
        loop {
            let wait = {
                let m = self.last.lock().await;
                match m.get(host) {
                    Some(t) => {
                        let gap_d = Duration::from_millis(gap);
                        t.checked_add(gap_d)
                            .and_then(|d| d.checked_duration_since(Instant::now()))
                    }
                    None => None,
                }
            };
            match wait {
                Some(d) => tokio::time::sleep(d).await,
                None => break,
            }
        }
        let mut m = self.last.lock().await;
        m.insert(host.to_string(), Instant::now());
    }
}

async fn tcp_once(host: &str, port: u16, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

/// 2 denemeli TCP testi (arada kisa bekleme + jitter).
pub async fn tcp_ok(host: &str, port: u16, timeout: Duration, throttle: &HostThrottle) -> bool {
    for attempt in 0..2 {
        throttle.gate(host).await;
        if tcp_once(host, port, timeout).await {
            return true;
        }
        if attempt == 0 {
            // jitter: ayni hostlara ayni anda yuklenmemek icin
            let mut h = DefaultHasher::new();
            (host, Instant::now()).hash(&mut h);
            let jitter = 200 + h.finish() % 400;
            tokio::time::sleep(Duration::from_millis(jitter)).await;
        }
    }
    false
}

/// Tum universe icin TCP testi. Donus: fingerprint -> canli mi.
pub async fn test_many(
    items: &[Arc<Item>],
    workers: usize,
    timeout: Duration,
    gap_ms: u64,
) -> HashMap<String, bool> {
    let sem = Arc::new(Semaphore::new(workers.max(1)));
    let throttle = Arc::new(HostThrottle::new(gap_ms));
    let mut set = tokio::task::JoinSet::new();
    for it in items {
        let (it, sem, throttle) = (Arc::clone(it), Arc::clone(&sem), Arc::clone(&throttle));
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            let ok = tcp_ok(&it.host, it.port, timeout, &throttle).await;
            (it.fingerprint.clone(), ok)
        });
    }
    let mut out = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok((fp, ok)) = r {
            out.insert(fp, ok);
        }
    }
    out
}

/// Host cesitliligi raporu (tek hostun listeyi domine etmemesi icin gozlem).
pub fn host_histogram(items: &[Arc<Item>], fps: &HashSet<String>) -> Vec<(String, usize)> {
    let mut m: HashMap<String, usize> = HashMap::new();
    for it in items {
        if fps.contains(&it.fingerprint) {
            *m.entry(it.host.clone()).or_default() += 1;
        }
    }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(10);
    v
}
