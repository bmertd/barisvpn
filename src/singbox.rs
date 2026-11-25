use crate::parse::{Item, Proto};
use crate::tcp::HostThrottle;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

// ---------------------------------------------------------------------------
// sing-box cozumu
// ---------------------------------------------------------------------------

pub fn resolve_singbox(arg: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = arg {
        if is_exec(p) {
            return Some(p.to_path_buf());
        }
        eprintln!("[UYARI] sing-box bulunamadi: {}", p.display());
        return None;
    }
    if let Ok(env) = std::env::var("SINGBOX_PATH") {
        let p = PathBuf::from(env);
        if is_exec(&p) {
            return Some(p);
        }
    }
    for cand in ["./sing-box", "sing-box"] {
        let p = PathBuf::from(cand);
        if is_exec(&p) {
            return Some(p);
        }
    }
    // PATH uzerinden `sing-box version` dene
    if std::process::Command::new("sing-box")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Some(PathBuf::from("sing-box"));
    }
    None
}

fn is_exec(p: &Path) -> bool {
    if p == Path::new("sing-box") {
        return false; // PATH kontrolu ayrica yapiliyor
    }
    p.exists()
}

fn qmap(url: &Url) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in url.query_pairs() {
        m.entry(k.to_ascii_lowercase()).or_insert(v.into_owned());
    }
    m
}

fn qp(m: &HashMap<String, String>, key: &str) -> String {
    m.get(key).cloned().unwrap_or_default()
}

// ---- transport ----

// ---- transport ----
// NOT: sing-box'ta "tcp" diye bir transport YOK; duz TCP = transport alanini
// tamamen atlamak. http-header'li TCP kamuflaji cekirdekte karsiliksiz,
// o durumda da duz TCP denenir (basarisizsa grace/history korur).
fn transport(net: &str, m: &HashMap<String, String>, default_host: &str) -> Option<Value> {
    let path = {
        let p = qp(m, "path");
        if p.is_empty() {
            qp(m, "serviceName")
        } else {
            p
        }
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    let host = {
        let h = qp(m, "host");
        if h.is_empty() {
            default_host.to_string()
        } else {
            h
        }
    };
    match net {
        "ws" => {
            let mut hdr = serde_json::Map::new();
            if !host.is_empty() {
                hdr.insert("Host".to_string(), Value::String(host));
            }
            Some(json!({"type":"ws","path":path,"headers":hdr}))
        }
        "grpc" => {
            let svc = qp(m, "serviceName");
            Some(json!({"type":"grpc","service_name":svc}))
        }
        "http" | "h2" => {
            let mut hdr = serde_json::Map::new();
            if !host.is_empty() {
                hdr.insert("Host".to_string(), Value::String(host));
            }
            Some(json!({"type":"http","path":path,"headers":hdr}))
        }
        _ => None, // duz TCP (+http kamuflaj desteksiz): transport yok
    }
}

// ---- tls ----
// security "none" ise None doner: tls anahtari tamamen atlanir.
// Sebep: sing-box v1.14'te explicit `"tls":{"enabled":false}` bazi
// outbound'larda (vless) nil-pointer panic'e yol aciyor; anahtari
// atlamak duz-baglanti icin dogru ve calisan yol.
fn tls_block(
    security: &str,
    sni: &str,
    fp: &str,
    alpn: &str,
    pbk: &str,
    sid: &str,
) -> Option<Value> {
    match security {
        "tls" => {
            let mut t = serde_json::Map::new();
            t.insert("enabled".to_string(), Value::Bool(true));
            t.insert("server_name".to_string(), Value::String(sni.to_string()));
            t.insert("insecure".to_string(), Value::Bool(false));
            if !fp.is_empty() {
                t.insert("utls".to_string(), json!({"enabled":true,"fingerprint":fp}));
            }
            if !alpn.is_empty() {
                let v: Vec<Value> = alpn
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect();
                if !v.is_empty() {
                    t.insert("alpn".to_string(), Value::Array(v));
                }
            }
            Some(Value::Object(t))
        }
        "reality" => {
            let mut t = serde_json::Map::new();
            t.insert("enabled".to_string(), Value::Bool(true));
            t.insert("server_name".to_string(), Value::String(sni.to_string()));
            t.insert("insecure".to_string(), Value::Bool(false));
            let fingerprint = if fp.is_empty() { "chrome" } else { fp };
            t.insert(
                "utls".to_string(),
                json!({"enabled":true,"fingerprint":fingerprint}),
            );
            let mut r = serde_json::Map::new();
            r.insert("enabled".to_string(), Value::Bool(true));
            if !pbk.is_empty() {
                r.insert("public_key".to_string(), Value::String(pbk.to_string()));
            }
            if !sid.is_empty() {
                r.insert("short_id".to_string(), Value::String(sid.to_string()));
            }
            t.insert("reality".to_string(), Value::Object(r));
            Some(Value::Object(t))
        }
        _ => None,
    }
}

// ---- builders ----

fn build_vmess(item: &Item) -> Option<Value> {
    let body = item.original.split('#').next()?.get("vmess://".len()..)?;
    let t: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let norm = t.replace('-', "+").replace('_', "/");
    let mut padded = norm;
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = STANDARD.decode(&padded).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let o = v.as_object()?;
    let s = |k: &str| {
        o.get(k).and_then(|x| {
            if x.is_string() {
                x.as_str().map(|s| s.to_string())
            } else {
                Some(x.to_string())
            }
        })
    };
    let server = s("add")?;
    let port: u16 =
        o.get("port")
            .and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse::<u64>().ok()))? as u16;
    let uuid = s("id")?;
    let alter: u64 = o
        .get("aid")
        .and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse::<u64>().ok()))
        .unwrap_or(0);
    let net = s("net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let security = s("tls").unwrap_or_default().to_ascii_lowercase();
    let host = s("host").or_else(|| s("add")).unwrap_or_default();
    let path = s("path").unwrap_or_else(|| "/".into());
    let sni = s("sni")
        .map(|x| if x.is_empty() { host.clone() } else { x })
        .unwrap_or_else(|| host.clone());
    let mut m = HashMap::new();
    m.insert("path".to_string(), path);
    m.insert("host".to_string(), host.clone());
    m.insert(
        "serviceName".to_string(),
        s("serviceName").unwrap_or_default(),
    );
    m.insert("headerType".to_string(), s("type").unwrap_or_default());
    let tls = tls_block(
        if security == "tls" { "tls" } else { "none" },
        if sni.is_empty() { &server } else { &sni },
        &s("fp").unwrap_or_default(),
        &s("alpn").unwrap_or_default(),
        "",
        "",
    );
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("vmess".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(server));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("uuid".to_string(), Value::String(uuid));
    ob.insert(
        "security".to_string(),
        Value::String(s("scy").unwrap_or_else(|| "auto".into())),
    );
    ob.insert("alter_id".to_string(), json!(alter));
    if let Some(t) = transport(&net, &m, &host) {
        ob.insert("transport".to_string(), t);
    }
    if let Some(t) = tls {
        ob.insert("tls".to_string(), t);
    }
    Some(Value::Object(ob))
}

fn build_vless(url: &Url) -> Option<Value> {
    let m = qmap(url);
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let uuid = url.username().to_string();
    if uuid.is_empty() {
        return None;
    }
    let net = qp(&m, "type");
    let net = if net.is_empty() {
        "tcp".to_string()
    } else {
        net.to_ascii_lowercase()
    };
    let security = qp(&m, "security").to_ascii_lowercase();
    let security = if security.is_empty() {
        "none".to_string()
    } else {
        security
    };
    let sni = first_nonempty(&[qp(&m, "sni"), qp(&m, "host"), host.clone()]);
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("vless".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host.clone()));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("uuid".to_string(), Value::String(uuid));
    let flow = qp(&m, "flow");
    if !flow.is_empty() {
        ob.insert("flow".to_string(), Value::String(flow));
    }
    if let Some(t) = transport(&net, &m, &qp(&m, "host")) {
        ob.insert("transport".to_string(), t);
    }
    if let Some(t) = tls_block(
        &security,
        &sni,
        &qp(&m, "fp"),
        &qp(&m, "alpn"),
        &qp(&m, "pbk"),
        &qp(&m, "sid"),
    ) {
        ob.insert("tls".to_string(), t);
    }
    Some(Value::Object(ob))
}

fn build_trojan(url: &Url) -> Option<Value> {
    let m = qmap(url);
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let password = url.password().unwrap_or(url.username()).to_string();
    if password.is_empty() {
        return None;
    }
    let net = qp(&m, "type");
    let net = if net.is_empty() {
        "tcp".to_string()
    } else {
        net.to_ascii_lowercase()
    };
    let security = qp(&m, "security");
    let security = if security.is_empty() {
        "tls".to_string()
    } else {
        security.to_ascii_lowercase()
    };
    let sni = first_nonempty(&[qp(&m, "sni"), qp(&m, "host"), host.clone()]);
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("trojan".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("password".to_string(), Value::String(password));
    if let Some(t) = transport(&net, &m, &qp(&m, "host")) {
        ob.insert("transport".to_string(), t);
    }
    if let Some(t) = tls_block(
        &security,
        &sni,
        &qp(&m, "fp"),
        &qp(&m, "alpn"),
        &qp(&m, "pbk"),
        &qp(&m, "sid"),
    ) {
        ob.insert("tls".to_string(), t);
    }
    Some(Value::Object(ob))
}

fn build_ss(item: &Item) -> Option<Value> {
    // parse.rs ile ayni mantik, sadelestirilmis
    let nofrag = item.original.split('#').next()?;
    let body = nofrag.get("ss://".len()..)?;
    let (main, _) = match body.find('?') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };
    let mut main = main.to_string();
    if !main.contains('@') {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let t: String = main.chars().filter(|c| !c.is_whitespace()).collect();
        let norm = t.replace('-', "+").replace('_', "/");
        let mut p = norm;
        while p.len() % 4 != 0 {
            p.push('=');
        }
        main = String::from_utf8(STANDARD.decode(&p).ok()?).ok()?;
    }
    let at = main.rfind('@')?;
    let (mut userinfo, hostport) = (main[..at].to_string(), &main[at + 1..]);
    if !userinfo.contains(':') {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let norm = userinfo.replace('-', "+").replace('_', "/");
        let mut p = norm;
        while p.len() % 4 != 0 {
            p.push('=');
        }
        userinfo = String::from_utf8(STANDARD.decode(&p).ok()?).ok()?;
    }
    let c = userinfo.find(':')?;
    let (method, password) = (&userinfo[..c], &userinfo[c + 1..]);
    let c = hostport.rfind(':')?;
    let (host, port): (String, u16) = (
        hostport[..c]
            .trim()
            .trim_matches(&['[', ']'][..])
            .to_string(),
        hostport[c + 1..].trim().parse().ok()?,
    );
    Some(json!({
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method.to_ascii_lowercase(),
        "password": password,
    }))
}

fn build_hysteria2(url: &Url) -> Option<Value> {
    let m = qmap(url);
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    // sifre: userinfo (password varsa o, yoksa username) veya `password`/`auth` param
    let mut pw = url.password().unwrap_or("").to_string();
    if pw.is_empty() {
        pw = first_nonempty(&[
            qp(&m, "password"),
            qp(&m, "auth"),
            url.username().to_string(),
        ]);
    }
    if pw.is_empty() {
        return None;
    }
    let sni = first_nonempty(&[qp(&m, "sni"), qp(&m, "peer"), qp(&m, "host"), host.clone()]);
    let insecure = matches!(qp(&m, "insecure").as_str(), "1" | "true");
    let mut tls = serde_json::Map::new();
    tls.insert("enabled".to_string(), Value::Bool(true));
    tls.insert("server_name".to_string(), Value::String(sni));
    tls.insert("insecure".to_string(), Value::Bool(insecure));
    tls.insert("alpn".to_string(), json!(["h3"]));
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("hysteria2".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("password".to_string(), Value::String(pw));
    // obfs (salamander)
    let obfs = qp(&m, "obfs");
    if !obfs.is_empty() && obfs.to_ascii_lowercase() != "none" {
        let opw = qp(&m, "obfs-password");
        let opw = if opw.is_empty() {
            qp(&m, "obfsPassword")
        } else {
            opw
        };
        ob.insert("obfs".to_string(), json!({"type": obfs, "password": opw}));
    }
    let up = qp(&m, "up");
    let down = qp(&m, "down");
    if !up.is_empty() {
        ob.insert("up_mbps".to_string(), Value::String(up));
    }
    if !down.is_empty() {
        ob.insert("down_mbps".to_string(), Value::String(down));
    }
    ob.insert("tls".to_string(), Value::Object(tls));
    Some(Value::Object(ob))
}

fn build_hysteria(url: &Url) -> Option<Value> {
    let m = qmap(url);
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let auth = first_nonempty(&[
        qp(&m, "auth"),
        url.password().unwrap_or("").to_string(),
        url.username().to_string(),
    ]);
    if auth.is_empty() {
        return None;
    }
    let sni = first_nonempty(&[qp(&m, "sni"), qp(&m, "peer"), qp(&m, "host"), host.clone()]);
    let insecure = matches!(qp(&m, "insecure").as_str(), "1" | "true");
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("hysteria".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("auth_str".to_string(), Value::String(auth));
    let protocol = qp(&m, "protocol");
    if !protocol.is_empty() {
        ob.insert("protocol".to_string(), Value::String(protocol));
    }
    let obfs = qp(&m, "obfs");
    if !obfs.is_empty() && obfs.to_ascii_lowercase() != "none" {
        ob.insert("obfs".to_string(), Value::String(obfs));
    }
    for (k, nk) in [
        ("upmbps", "up_mbps"),
        ("downmbps", "down_mbps"),
        ("up", "up_mbps"),
        ("down", "down_mbps"),
    ] {
        let v = qp(&m, k);
        if !v.is_empty() {
            if let Ok(n) = v.parse::<u64>() {
                ob.insert(nk.to_string(), json!(n));
            }
        }
    }
    ob.insert(
        "tls".to_string(),
        json!({"enabled": true, "server_name": sni, "insecure": insecure}),
    );
    Some(Value::Object(ob))
}

fn build_tuic(url: &Url) -> Option<Value> {
    let m = qmap(url);
    let host = url.host_str()?.to_string();
    let port = url.port().unwrap_or(443);
    let uuid = url.username().to_string();
    let password = url.password().unwrap_or("").to_string();
    if uuid.is_empty() || password.is_empty() {
        return None;
    }
    let sni = first_nonempty(&[qp(&m, "sni"), host.clone()]);
    let insecure = matches!(qp(&m, "insecure").as_str(), "1" | "true");
    let alpn_v: Vec<Value> = {
        let a = qp(&m, "alpn");
        if a.is_empty() {
            vec![Value::String("h3".into())]
        } else {
            a.split(',')
                .map(|s| Value::String(s.trim().to_string()))
                .collect()
        }
    };
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), Value::String("tuic".into()));
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host));
    ob.insert("server_port".to_string(), json!(port));
    ob.insert("uuid".to_string(), Value::String(uuid));
    ob.insert("password".to_string(), Value::String(password));
    let cc = qp(&m, "congestion_control");
    ob.insert(
        "congestion_control".to_string(),
        Value::String(if cc.is_empty() { "cubic".into() } else { cc }),
    );
    ob.insert(
        "udp_relay_mode".to_string(),
        Value::String({
            let u = qp(&m, "udp_relay_mode");
            if u.is_empty() {
                "native".into()
            } else {
                u
            }
        }),
    );
    ob.insert(
        "tls".to_string(),
        json!({"enabled": true, "server_name": sni, "insecure": insecure, "alpn": alpn_v}),
    );
    Some(Value::Object(ob))
}

fn build_socks_http(proto: Proto, url: &Url) -> Option<Value> {
    let host = url.host_str()?.to_string();
    let port = url
        .port()
        .unwrap_or(if proto == Proto::Http { 80 } else { 1080 });
    let mut ob = serde_json::Map::new();
    ob.insert(
        "type".to_string(),
        Value::String(if proto == Proto::Http {
            "http".into()
        } else {
            "socks".into()
        }),
    );
    ob.insert("tag".to_string(), Value::String("proxy".into()));
    ob.insert("server".to_string(), Value::String(host));
    ob.insert("server_port".to_string(), json!(port));
    if !url.username().is_empty() {
        ob.insert(
            "username".to_string(),
            Value::String(url.username().to_string()),
        );
    }
    if let Some(pw) = url.password() {
        ob.insert("password".to_string(), Value::String(pw.to_string()));
    }
    if proto == Proto::Socks {
        ob.insert("version".to_string(), Value::String("5".into()));
    }
    Some(Value::Object(ob))
}

fn first_nonempty(v: &[String]) -> String {
    v.iter()
        .find(|s| !s.is_empty())
        .cloned()
        .unwrap_or_default()
}

/// URI -> sing-box outbound JSON. Desteklenmeyenler (ssr, eksik anahtarli wireguard) None.
pub fn build_outbound(item: &Item) -> Option<Value> {
    match item.proto {
        Proto::Vmess => build_vmess(item),
        Proto::Vless => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_vless(&u)),
        Proto::Trojan => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_trojan(&u)),
        Proto::Shadowsocks => build_ss(item),
        Proto::Hysteria2 => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_hysteria2(&u)),
        Proto::Hysteria => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_hysteria(&u)),
        Proto::Tuic => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_tuic(&u)),
        Proto::Socks | Proto::Http => Url::parse(item.original.split('#').next()?)
            .ok()
            .and_then(|u| build_socks_http(item.proto, &u)),
        // ssr: bakimi yapilan cekirdeklerde destek yok -> bilerek tunel disi.
        // wireguard: URI standardi yok, anahtarlar genelde eksik -> tunel disi.
        Proto::ShadowsocksR | Proto::Wireguard => None,
    }
}

// ---------------------------------------------------------------------------
// tunel testi
// ---------------------------------------------------------------------------

fn free_port() -> Option<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    l.local_addr().ok().map(|a| a.port())
}

async fn wait_port(port: u16, child: &mut tokio::process::Child, timeout: Duration) -> bool {
    let end = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < end {
        if child.try_wait().ok().flatten().is_some() {
            return false; // sing-box config hatasiyla coktu
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn fetch_via(client: &reqwest::Client, url: &str) -> (bool, String) {
    match client.get(url).send().await {
        Ok(r) => {
            let s = r.status().as_u16();
            if (200..400).contains(&s) {
                (true, format!("http-{s}"))
            } else {
                (false, format!("http-{s}"))
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "timeout".to_string())
            } else {
                (false, "fetch-fail".to_string())
            }
        }
    }
}

/// Tek config icin tam tunel testi. Donus: (calisiyor mu, sebep).
///
/// Birincil hedefe transport-hatasiyla erisilemezse (timeout/fetch-fail:
/// hedef-kaynakli ya da GitHub-IP blok suphesi) ayni tunel uzerinden yedek
/// hedef bir kez denenir. HTTP status donduyse (200 de 403 de olsa) tunel
/// veri tasiyordur, sonuc kesindir, yedek denenmez.
pub async fn test_one(
    item: &Item,
    singbox: &Path,
    test_url: &str,
    fallback_url: &str,
    proxy_timeout: Duration,
    boot_timeout: Duration,
) -> (bool, String) {
    let outbound = match build_outbound(item) {
        Some(o) => o,
        None => return (false, "unsupported".to_string()),
    };
    let port = match free_port() {
        Some(p) => p,
        None => return (false, "no-port".to_string()),
    };
    let cfg = json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy", "auto_detect_interface": false}
    });
    let cfg_path =
        std::env::temp_dir().join(format!("barisvpn-{}-{}.json", std::process::id(), port));
    if tokio::fs::write(&cfg_path, serde_json::to_string(&cfg).unwrap_or_default())
        .await
        .is_err()
    {
        return (false, "cfg-write-fail".to_string());
    }

    let mut child = match tokio::process::Command::new(singbox)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tokio::fs::remove_file(&cfg_path).await;
            return (false, format!("spawn-fail:{e}"));
        }
    };

    let outcome = async {
        if !wait_port(port, &mut child, boot_timeout).await {
            return (false, "singbox-not-up".to_string());
        }
        let proxy = match reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")) {
            Ok(p) => p,
            Err(_) => return (false, "proxy-build-fail".to_string()),
        };
        let client = match reqwest::Client::builder()
            .proxy(proxy)
            .timeout(proxy_timeout)
            .build()
        {
            Ok(c) => c,
            Err(_) => return (false, "client-fail".to_string()),
        };
        // Birincil hedef. HTTP status donerse tunel veri tasiyor demektir.
        let primary = fetch_via(&client, test_url).await;
        if primary.0 || primary.1.starts_with("http-") {
            return primary;
        }
        // Transport hatasi: hedef-kaynakli blok ihtimaline karsi yedek hedef.
        if fallback_url != test_url {
            let fb = fetch_via(&client, fallback_url).await;
            if fb.0 || fb.1.starts_with("http-") {
                return fb;
            }
            return (false, format!("{}+{}", primary.1, fb.1));
        }
        primary
    }
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = tokio::fs::remove_file(&cfg_path).await;
    outcome
}

/// Tunel testi: 2 deneme (rate-limit yanlis-negatifine karsi), host-throttle'li.
pub async fn test_many(
    items: &[Arc<Item>],
    singbox: &Path,
    test_url: &str,
    fallback_url: &str,
    workers: usize,
    proxy_timeout: Duration,
    boot_timeout: Duration,
) -> HashMap<String, (bool, String)> {
    let sem = Arc::new(Semaphore::new(workers.max(1)));
    let throttle = Arc::new(HostThrottle::new(800));
    let singbox = singbox.to_path_buf();
    let test_url = test_url.to_string();
    let fallback_url = fallback_url.to_string();
    let mut set = tokio::task::JoinSet::new();
    for it in items {
        let (it, sem, throttle, singbox, test_url, fallback_url) = (
            Arc::clone(it),
            Arc::clone(&sem),
            Arc::clone(&throttle),
            singbox.clone(),
            test_url.clone(),
            fallback_url.clone(),
        );
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            // builder desteklemiyorsa bosuna bekleme
            if build_outbound(&it).is_none() {
                return (it.fingerprint.clone(), (false, "unsupported".to_string()));
            }
            let mut last = (false, "unknown".to_string());
            for attempt in 0..2 {
                throttle.gate(&it.host).await;
                let r = test_one(
                    &it,
                    &singbox,
                    &test_url,
                    &fallback_url,
                    proxy_timeout,
                    boot_timeout,
                )
                .await;
                last = r;
                if last.0 {
                    break;
                }
                // "unsupported"/"singbox-not-up" gibi deterministik hatalarda retry yok
                if last.1 == "unsupported" || last.1 == "singbox-not-up" {
                    break;
                }
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                }
            }
            (it.fingerprint.clone(), last)
        });
    }
    let mut out = HashMap::new();
    while let Some(r) = set.join_next().await {
        if let Ok((fp, v)) = r {
            out.insert(fp, v);
        }
    }
    out
}

/// Destek istatistigi: hangi protokolden kac tanesi tunel-testine girebildi.
pub fn support_stats(items: &[Arc<Item>]) -> Vec<(String, usize, usize)> {
    let mut m: HashMap<String, (usize, usize)> = HashMap::new();
    for it in items {
        let e = m.entry(it.proto.as_str().to_string()).or_default();
        e.0 += 1;
        if build_outbound(it).is_some() {
            e.1 += 1;
        }
    }
    let mut v: Vec<_> = m.into_iter().map(|(k, (t, s))| (k, t, s)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

#[allow(dead_code)]
pub fn reason_histogram(results: &HashMap<String, (bool, String)>) -> Vec<(String, usize)> {
    let mut m: HashMap<String, usize> = HashMap::new();
    for (_, reason) in results.values() {
        if !reason.starts_with("http-2") {
            *m.entry(reason.clone()).or_default() += 1;
        }
    }
    let mut v: Vec<_> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(10);
    v
}

#[allow(unused_imports)]
pub fn _use_hashset(_: &HashSet<String>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_item;

    fn outbound_type(uri: &str) -> Option<String> {
        let it = parse_item(uri)?;
        build_outbound(&it)?
            .get("type")?
            .as_str()
            .map(|s| s.to_string())
    }

    #[test]
    fn builders_cover_supported_protos() {
        let cases = [
            ("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=reality&pbk=abc&sid=01&sni=h.example&fp=chrome&type=grpc&serviceName=svc&encryption=none", "vless"),
            ("vless://u@h.example:443?security=tls&sni=h.example&type=ws&path=%2Fy&host=h.example", "vless"),
            ("trojan://pw@h.example:443?sni=h.example&type=tcp&headerType=http", "trojan"),
            ("ss://aes-256-gcm:test@h.example:8388", "shadowsocks"),
            ("hysteria2://pw@h.example:443?sni=h.example&obfs=salamander&obfs-password=obfs1", "hysteria2"),
            ("hy2://pw@h.example:443?sni=h.example", "hysteria2"),
            ("hysteria://pw@h.example:443?protocol=udp&upmbps=20&downmbps=100&sni=h.example", "hysteria"),
            ("tuic://11111111-1111-1111-1111-111111111111:pw@h.example:443?congestion_control=bbr&sni=h.example", "tuic"),
            ("socks://u:p@h.example:1080", "socks"),
        ];
        for (uri, want) in cases {
            assert_eq!(outbound_type(uri).as_deref(), Some(want), "builder: {uri}");
        }
    }

    #[test]
    fn unsupported_have_no_outbound() {
        // ssr: bakimli cekirdek destegi yok -> tunel disi (TCP + parse yine var)
        let it = parse_item("ssr://aG9zdC5leGFtcGxlOjQ0MzpvcmlnaW46YWVzLTEyOC1jZmI6cGxhaW46YU1qazNOUT09Lz9vYmZzcGFyYW09YU1qazNOUT09").unwrap();
        assert!(build_outbound(&it).is_none());
    }

    #[test]
    fn reality_fields_present() {
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=reality&pbk=PUBKEY&sid=SHORT&sni=h.example&fp=chrome").unwrap();
        let o = build_outbound(&it).unwrap();
        assert_eq!(o["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(o["tls"]["reality"]["short_id"], "SHORT");
    }
}
