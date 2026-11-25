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
        sanitize_path(&path)
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

// sing-box'un tanidigi uTLS parmak izleri. Kaynaklarda `fp=null`,
// `fp=unsafe`, `fp=qq` gibi sacmaliklar var; bilinmeyeni gecirmek
// sing-box'i boot'ta patlatir ("unknown uTLS fingerprint"), o yuzden
// whitelist disi deger atilir (duz TLS ile devam edilir).
fn sanitize_utls_fp(fp: &str) -> &str {
    match fp.to_ascii_lowercase().as_str() {
        "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random"
        | "randomized" | "randomalpn" => fp,
        _ => "",
    }
}

/// reality short_id gecerli mi? (sing-box cift-uzunluk hex ister;
// "0" gibi degerler boot'ta patlatir). Gecersizse atilir.
fn valid_short_id(sid: &str) -> bool {
    !sid.is_empty() && sid.len() % 2 == 0 && sid.chars().all(|c| c.is_ascii_hexdigit())
}

/// ws/http path'indeki sahte `%'leri kodla ("invalid URL escape" patlamasina karsi).
/// Gecerli %XX kacislari ve UTF-8 aynen korunur.
fn sanitize_path(p: &str) -> String {
    let b = p.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && !(i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit())
        {
            out.extend_from_slice(b"%25");
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| p.to_string())
}
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
            let fp = sanitize_utls_fp(fp);
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
            let fp = sanitize_utls_fp(fp);
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
            if valid_short_id(sid) {
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
    // `scy=null` gibi sacmaliklar boot'ta patlatir; bilinmeyen -> auto.
    let scy = s("scy")
        .unwrap_or_else(|| "auto".into())
        .to_ascii_lowercase();
    let scy = match scy.as_str() {
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" => scy,
        _ => "auto".to_string(),
    };
    ob.insert("security".to_string(), Value::String(scy));
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
    // sing-box sadece bu flow'lari bilir; "xtls-rprx-vision-udp443" gibi
    // Xray-ozel degerler boot'ta patlatir. Bilinmeyen flow atilir (sans verilir).
    let flow = qp(&m, "flow").to_ascii_lowercase();
    if flow == "xtls-rprx-vision" {
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
    // sing-box metod adlari: kisa yazimlari gercek adlara cevir
    // (chacha20-poly1305 boot'ta patlatir).
    let method = match method.to_ascii_lowercase().as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        m => m.to_string(),
    };
    Some(json!({
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "method": method,
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
    fallback: Option<&str>,
    proxy_timeout: Duration,
    boot_timeout: Duration,
) -> (bool, String) {
    let outbound = match build_outbound(item) {
        Some(o) => o,
        None => return (false, "unsupported".to_string()),
    };

    // Boot: en fazla 2 deneme, her seferinde YENI bos port.
    // Sebep: free_port() bind-edip birakir; yogun paralellikte baska test
    // araya girip ayni portu kapabilir -> sing-box bind-hatasiyla cokup
    // "not-up" gorunur. Taze portla retry yaris durumunu eler; gercekten
    // bozuk config ise aninda yine coker (ucuz).
    let mut child_opt: Option<tokio::process::Child> = None;
    let mut active_port = 0u16;
    let mut cfg_path = std::path::PathBuf::new();
    for _ in 0..2 {
        let port = match free_port() {
            Some(p) => p,
            None => return (false, "no-port".to_string()),
        };
        let cfg = json!({
            "log": {"level": "error"},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [outbound.clone(), {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy", "auto_detect_interface": false}
        });
        cfg_path = std::env::temp_dir().join(format!("barisvpn-{}-{port}", std::process::id()));
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
        if wait_port(port, &mut child, boot_timeout).await {
            active_port = port;
            child_opt = Some(child);
            break;
        }
        // boot olmadi: temizle, taze portla bir daha dene
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = tokio::fs::remove_file(&cfg_path).await;
    }
    let mut child = match child_opt {
        Some(c) => c,
        None => return (false, "singbox-not-up".to_string()),
    };
    let port = active_port;

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
        // Transport hatasi: hedef-kaynakli blok ihtimaline karsi yedek hedef,
        // ama KISA butceyle (yavasligi patlatmamak icin).
        if let Some(fb) = fallback {
            if fb != test_url {
                let fb_budget = proxy_timeout.min(Duration::from_secs(5));
                let capped = async {
                    match tokio::time::timeout(fb_budget, client.get(fb).send()).await {
                        Ok(Ok(r)) => {
                            let s = r.status().as_u16();
                            if (200..400).contains(&s) {
                                (true, format!("http-{s}"))
                            } else {
                                (false, format!("http-{s}"))
                            }
                        }
                        Ok(Err(e)) => {
                            if e.is_timeout() {
                                (false, "timeout".to_string())
                            } else {
                                (false, "fetch-fail".to_string())
                            }
                        }
                        Err(_) => (false, "timeout".to_string()),
                    }
                }
                .await;
                if capped.0 || capped.1.starts_with("http-") {
                    return capped;
                }
                return (false, format!("{}+{}", primary.1, capped.1));
            }
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
/// Yedek hedef sadece 1. denemede kullanilir (hizi korumak icin); ilerleme
/// her 25 tamamlananda loglanir ki "takildi" hissi olusmasin.
pub async fn test_many(
    items: &[Arc<Item>],
    singbox: &Path,
    test_url: &str,
    fallback_url: &str,
    workers: usize,
    proxy_timeout: Duration,
    boot_timeout: Duration,
) -> HashMap<String, (bool, String)> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    let sem = Arc::new(Semaphore::new(workers.max(1)));
    let throttle = Arc::new(HostThrottle::new(800));
    let singbox = singbox.to_path_buf();
    let test_url = test_url.to_string();
    let fallback_url = fallback_url.to_string();
    // yedek hedefe ayri butce yok: test_one icinde primary'e gore cap'lenir
    let total = items.len();
    let done = Arc::new(AtomicUsize::new(0));
    let ok_n = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    // teshis icin: sebep basina ilk 3 ornek URI (log sismemesi icin cap'li)
    let examples: Arc<std::sync::Mutex<HashMap<String, Vec<String>>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let mut set = tokio::task::JoinSet::new();
    for it in items {
        let (it, sem, throttle, singbox, test_url, fallback_url, done, ok_n, examples) = (
            Arc::clone(it),
            Arc::clone(&sem),
            Arc::clone(&throttle),
            singbox.clone(),
            test_url.clone(),
            fallback_url.clone(),
            Arc::clone(&done),
            Arc::clone(&ok_n),
            Arc::clone(&examples),
        );
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            // builder desteklemiyorsa bosuna bekleme
            if build_outbound(&it).is_none() {
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d % 25 == 0 || d == total {
                    println!(
                        "  tunel-test {d}/{total} (calisan: {}, {:.0}sn)",
                        ok_n.load(Ordering::Relaxed),
                        start.elapsed().as_secs_f64()
                    );
                }
                return (it.fingerprint.clone(), (false, "unsupported".to_string()));
            }
            let mut last = (false, "unknown".to_string());
            for attempt in 0..2 {
                throttle.gate(&it.host).await;
                // 1. deneme tam butce + yedek hedef; 2. deneme kisa butce
                // (yavas ama saglam sunucu 1. denemede zaten yakalanir, 2.'si
                // sadece flake sigortasidir) ve yedek hedef yok.
                let to = if attempt == 0 {
                    proxy_timeout
                } else {
                    proxy_timeout.min(Duration::from_secs(5))
                };
                let fb = if attempt == 0 {
                    Some(fallback_url.as_str())
                } else {
                    None
                };
                let r = test_one(&it, &singbox, &test_url, fb, to, boot_timeout).await;
                last = r;
                if last.0 {
                    break;
                }
                // "unsupported"/"singbox-not-up" gibi deterministik hatalarda retry yok
                if last.1 == "unsupported" || last.1 == "singbox-not-up" {
                    break;
                }
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            }
            if last.0 {
                ok_n.fetch_add(1, Ordering::Relaxed);
            } else if let Ok(mut ex) = examples.lock() {
                let v = ex.entry(last.1.clone()).or_default();
                if v.len() < 3 {
                    v.push(it.original.clone());
                }
            }
            let d = done.fetch_add(1, Ordering::Relaxed) + 1;
            if d % 25 == 0 || d == total {
                println!(
                    "  tunel-test {d}/{total} (calisan: {}, {:.0}sn)",
                    ok_n.load(Ordering::Relaxed),
                    start.elapsed().as_secs_f64()
                );
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
    if let Ok(ex) = examples.lock() {
        let mut rs: Vec<_> = ex.iter().collect();
        rs.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (reason, uris) in rs.iter().take(6) {
            println!("  ornek({reason}):");
            for u in uris.iter().take(3) {
                let short: String = u.chars().take(160).collect();
                println!("    {short}");
            }
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

    /// DUMP_CHECK=1 /tmp/chk ile calistir: kaynaklardaki tum URI'ler icin tam
    /// sing-box config uret; sonra `sing-box check` ile hangileri boot'ta
    /// patliyor bulunur (singbox-not-up sebeplerini avlamak icin).
    #[test]
    fn dump_configs_for_check() {
        if std::env::var("DUMP_CHECK").is_err() {
            return;
        }
        let outdir = std::env::var("DUMP_DIR").unwrap_or_else(|_| "/tmp/chk".into());
        std::fs::create_dir_all(&outdir).unwrap();
        let mut files: Vec<String> = Vec::new();
        for src in [
            "/tmp/real/s1.txt",
            "/tmp/real/s2.txt",
            "/tmp/full/super.txt",
        ] {
            if let Ok(t) = std::fs::read_to_string(src) {
                files.push(t);
            }
        }
        let mut seen = std::collections::HashSet::new();
        let mut n = 0;
        for content in files {
            let decoded = crate::fetch::decode_if_b64(&content);
            for uri in crate::fetch::extract_uris(&decoded) {
                let Some(it) = parse_item(&uri) else { continue };
                if !seen.insert(it.fingerprint.clone()) {
                    continue;
                }
                let Some(ob) = build_outbound(&it) else {
                    continue;
                };
                let cfg = serde_json::json!({
                    "log": {"level": "error"},
                    "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 14499}],
                    "outbounds": [ob, {"type": "direct", "tag": "direct"}],
                    "route": {"final": "proxy", "auto_detect_interface": false}
                });
                let p = format!("{}/{}.json", outdir, it.fingerprint);
                std::fs::write(p, serde_json::to_string(&cfg).unwrap()).unwrap();
                n += 1;
            }
        }
        eprintln!("dump: {n} config -> {outdir}");
    }

    #[test]
    fn reality_fields_present() {
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=reality&pbk=PUBKEY&sid=01ab&sni=h.example&fp=chrome").unwrap();
        let o = build_outbound(&it).unwrap();
        assert_eq!(o["tls"]["reality"]["public_key"], "PUBKEY");
        assert_eq!(o["tls"]["reality"]["short_id"], "01ab");
    }

    #[test]
    fn garbage_params_sanitized_not_fatal() {
        // fp=null/unsafe -> utls atilir, TLS kalir
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls&sni=h.example&fp=null").unwrap();
        let o = build_outbound(&it).unwrap();
        assert!(o.get("utls").is_none());
        assert!(o["tls"].get("utls").is_none());
        // Xray-ozel flow atilir
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls&flow=xtls-rprx-vision-udp443").unwrap();
        let o = build_outbound(&it).unwrap();
        assert!(o.get("flow").is_none());
        // gecerli flow korunur
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls&flow=xtls-rprx-vision").unwrap();
        assert_eq!(build_outbound(&it).unwrap()["flow"], "xtls-rprx-vision");
        // ss metod aliasi
        let it = parse_item("ss://chacha20-poly1305:test@h.example:8388").unwrap();
        assert_eq!(
            build_outbound(&it).unwrap()["method"],
            "chacha20-ietf-poly1305"
        );
        // vmess scy=null -> auto
        use base64::{engine::general_purpose::STANDARD as S, Engine as _};
        let j = r#"{"v":"2","add":"h.example","port":443,"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","aid":0,"net":"tcp","scy":"null"}"#;
        let it = parse_item(&format!("vmess://{}", S.encode(j))).unwrap();
        assert_eq!(build_outbound(&it).unwrap()["security"], "auto");
        // reality sid "0" atilir, pbk korunur
        let it = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=reality&pbk=K&sid=0&sni=h.example").unwrap();
        let o = build_outbound(&it).unwrap();
        assert!(o["tls"]["reality"].get("short_id").is_none());
        // path'teki sahte % kodlanir
        assert_eq!(sanitize_path("/a%b"), "/a%25b");
        assert_eq!(sanitize_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(sanitize_path("/çalışır"), "/çalışır");
    }
}
