use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    ShadowsocksR,
    Hysteria2,
    Hysteria,
    Tuic,
    Wireguard,
    Socks,
    Http,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Vmess => "vmess",
            Proto::Vless => "vless",
            Proto::Trojan => "trojan",
            Proto::Shadowsocks => "ss",
            Proto::ShadowsocksR => "ssr",
            Proto::Hysteria2 => "hysteria2",
            Proto::Hysteria => "hysteria",
            Proto::Tuic => "tuic",
            Proto::Wireguard => "wireguard",
            Proto::Socks => "socks",
            Proto::Http => "http",
        }
    }
}

/// Baglanti kimligi cozumlenmis tek config.
#[derive(Debug, Clone)]
pub struct Item {
    /// Ilk gorulen ham URI (ciktiya bu yazilir).
    pub original: String,
    pub proto: Proto,
    /// Kucultulmus host.
    pub host: String,
    /// Acik port (yoksa protokol varsayilani).
    pub port: u16,
    /// sha256(canonical) hex. Dedup + history anahtari.
    pub fingerprint: String,
    /// Sadece baglantiyi tanimlayan normalize form (#isim YOK).
    pub canonical: String,
}

pub fn scheme_of(uri: &str) -> Option<String> {
    let i = uri.find("://")?;
    Some(uri[..i].to_ascii_lowercase())
}

fn b64_padded(s: &str) -> String {
    let mut o = s.to_string();
    while o.len() % 4 != 0 {
        o.push('=');
    }
    o
}

fn decode_std_or_urlsafe(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let norm = t.replace('-', "+").replace('_', "/");
    if let Ok(b) = STANDARD.decode(b64_padded(&norm)) {
        return Some(b);
    }
    STANDARD.decode(b64_padded(&t)).ok()
}

fn strip_fragment(s: &str) -> &str {
    match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    }
}

/// Sorgu ciftlerini sirali + deterministik kodla.
fn canonical_query(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();
    pairs.sort();
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

fn default_port(proto: Proto) -> u16 {
    match proto {
        Proto::Wireguard => 51820,
        Proto::Socks => 1080,
        Proto::Http => 80,
        _ => 443,
    }
}

fn host_port(url: &Url, proto: Proto) -> Option<(String, u16)> {
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port().unwrap_or_else(|| default_port(proto));
    Some((host, port))
}

fn fmt_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

// ---------------- vmess ----------------

/// vmess JSON'undan baglanti alanlarini al (`ps`/`remarks` COP - isme gore degil baglantiya gore).
fn vmess_canonical(body_b64: &str) -> Option<(String, u16, String)> {
    let bytes = decode_std_or_urlsafe(body_b64.trim())?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let o = v.as_object()?;

    let get = |k: &str| {
        o.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let host = o
        .get("add")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port: u16 = o
        .get("port")
        .and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse::<u64>().ok()))
        .unwrap_or(443) as u16;

    // baglantiyi tanimlayan alanlar (ps bilerek yok)
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for k in [
        "v",
        "add",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "pbk",
        "sid",
        "spx",
        "serviceName",
        "headerType",
        "seed",
        "quicSecurity",
        "key",
        "mode",
    ] {
        if let Some(val) = o.get(k) {
            let s = if val.is_string() {
                val.as_str().unwrap_or("").to_string()
            } else {
                val.to_string()
            };
            let s = s.trim().to_string();
            if s.is_empty() {
                continue;
            }
            // case-insensitive alanlar
            let s = match k {
                "add" | "host" | "sni" | "net" | "type" | "tls" | "scy" | "fp" | "alpn"
                | "headerType" => s.to_ascii_lowercase(),
                "id" => s.to_ascii_lowercase(), // uuid
                "path" | "serviceName" | "seed" | "key" => s,
                _ => s,
            };
            m.insert(k.to_string(), s);
        }
    }
    // host/port tutarliligi
    m.insert("add".to_string(), host.clone());
    m.insert("port".to_string(), port.to_string());
    let _ = get("v");
    let canon = format!("vmess://{}", serde_json::to_string(&m).ok()?);
    Some((host, port, canon))
}

// ---------------- shadowsocks ----------------

fn split_ss_main(body: &str) -> Option<(String, String, String, u16, String)> {
    // returns (method, password, host, port, query)
    let nofrag = strip_fragment(body);
    let (main, query) = match nofrag.find('?') {
        Some(i) => (&nofrag[..i], &nofrag[i + 1..]),
        None => (nofrag, ""),
    };
    let mut main = main.to_string();
    if !main.contains('@') {
        let dec = decode_std_or_urlsafe(&main).and_then(|b| String::from_utf8(b).ok())?;
        if !dec.contains('@') {
            return None;
        }
        main = dec;
    }
    let at = main.rfind('@')?;
    let (userinfo, hostport) = (&main[..at], &main[at + 1..]);
    let (method, password) = if userinfo.contains(':') {
        let c = userinfo.find(':')?;
        (
            userinfo[..c].to_ascii_lowercase(),
            userinfo[c + 1..].to_string(),
        )
    } else {
        let dec = decode_std_or_urlsafe(userinfo).and_then(|b| String::from_utf8(b).ok())?;
        let c = dec.find(':')?;
        (dec[..c].to_ascii_lowercase(), dec[c + 1..].to_string())
    };
    let c = hostport.rfind(':')?;
    let host = hostport[..c]
        .trim()
        .trim_matches(&['[', ']'][..])
        .to_ascii_lowercase();
    let port: u16 = hostport[c + 1..].trim().parse().ok()?;
    if host.is_empty() || method.is_empty() {
        return None;
    }
    // query'yi sirala (plugin gibi baglanti alanlari dahil)
    let mut pairs: Vec<(String, String)> = Vec::new();
    if !query.is_empty() {
        for kv in query.split('&') {
            if kv.is_empty() {
                continue;
            }
            match kv.find('=') {
                Some(i) => pairs.push((kv[..i].to_ascii_lowercase(), kv[i + 1..].to_string())),
                None => pairs.push((kv.to_ascii_lowercase(), String::new())),
            }
        }
        pairs.sort();
    }
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        ser.append_pair(k, v);
    }
    Some((method, password, host, port, ser.finish()))
}

// ---------------- ssr ----------------

fn ssr_canonical(body: &str) -> Option<(String, u16, String)> {
    let nofrag = strip_fragment(body);
    // ssr govdesi her zaman base64 (urlsafe, padsiz olabilir)
    let t: String = nofrag.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = URL_SAFE_NO_PAD
        .decode(&t)
        .ok()
        .or_else(|| decode_std_or_urlsafe(&t))?;
    let dec = String::from_utf8(bytes).ok()?;
    let (main, params) = match dec.find("/?") {
        Some(i) => (&dec[..i], &dec[i + 2..]),
        None => (dec.as_str(), ""),
    };
    let parts: Vec<&str> = main.splitn(6, ':').collect();
    if parts.len() != 6 {
        return None;
    }
    let host = parts[0].trim().to_ascii_lowercase();
    let port: u16 = parts[1].trim().parse().ok()?;
    let proto = parts[2].trim().to_ascii_lowercase();
    let method = parts[3].trim().to_ascii_lowercase();
    let obfs = parts[4].trim().to_ascii_lowercase();
    let pass_b64 = parts[5].trim().replace('-', "+").replace('_', "/");
    let password = decode_std_or_urlsafe(&pass_b64)
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or(pass_b64.clone());
    if host.is_empty() {
        return None;
    }
    // remarks/group COP (isim); sadece baglanti paramlari kalir
    let mut keep: Vec<(String, String)> = Vec::new();
    for kv in params.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.find('=') {
            Some(i) => (&kv[..i], &kv[i + 1..]),
            None => (kv, ""),
        };
        match k.to_ascii_lowercase().as_str() {
            "obfsparam" | "protoparam" => {
                let dv = v.replace('-', "+").replace('_', "/");
                let plain = decode_std_or_urlsafe(&dv)
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| v.to_string());
                keep.push((k.to_ascii_lowercase(), plain));
            }
            _ => {}
        }
    }
    keep.sort();
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &keep {
        ser.append_pair(k, v);
    }
    let q = ser.finish();
    let canon = if q.is_empty() {
        format!("ssr://{host}:{port}:{proto}:{method}:{obfs}:{password}")
    } else {
        format!("ssr://{host}:{port}:{proto}:{method}:{obfs}:{password}?{q}")
    };
    Some((host, port, canon))
}

// ---------------- genel ----------------

fn generic_canonical(proto: Proto, scheme: &str, url: &Url) -> Option<(String, u16, String)> {
    let (host, port) = host_port(url, proto)?;
    let mut user = url.username().to_string();
    // uuid'ler case-insensitive
    if matches!(proto, Proto::Vless | Proto::Tuic) {
        // tuic'te username uuid'dir
        if proto == Proto::Vless || (proto == Proto::Tuic && !user.is_empty()) {
            // uuid formatindaysa kucult (heuristic: icinde - varsa)
            if user.contains('-') || proto == Proto::Vless {
                user = user.to_ascii_lowercase();
            }
        }
    }
    let userinfo = match url.password() {
        Some(pw) => format!("{user}:{pw}"),
        None => user,
    };
    let q = canonical_query(url);
    let canon = if q.is_empty() {
        format!("{scheme}://{userinfo}@{}:{port}", fmt_host(&host))
    } else {
        format!("{scheme}://{userinfo}@{}:{port}?{q}", fmt_host(&host))
    };
    Some((host, port, canon))
}

pub fn parse_item(raw: &str) -> Option<Item> {
    let uri = raw.trim().to_string();
    if uri.is_empty() {
        return None;
    }
    let scheme = scheme_of(&uri)?;
    let nofrag = strip_fragment(&uri);

    // vmess: ozel (base64 JSON)
    if scheme == "vmess" {
        let body = nofrag.get("vmess://".len()..)?;
        let (host, port, canon) = vmess_canonical(body)?;
        return Some(finish(uri, Proto::Vmess, host, port, canon));
    }
    // ss: ozel (cok formatli)
    if scheme == "ss" {
        let body = nofrag.get("ss://".len()..)?;
        let (method, password, host, port, q) = split_ss_main(body)?;
        let canon = if q.is_empty() {
            format!("ss://{method}:{password}@{}:{port}", fmt_host(&host))
        } else {
            format!("ss://{method}:{password}@{}:{port}?{q}", fmt_host(&host))
        };
        return Some(finish(uri, Proto::Shadowsocks, host, port, canon));
    }
    // ssr: ozel
    if scheme == "ssr" {
        let body = nofrag.get("ssr://".len()..)?;
        let (host, port, canon) = ssr_canonical(body)?;
        return Some(finish(uri, Proto::ShadowsocksR, host, port, canon));
    }

    // URL tabanlilar
    let (proto, canon_scheme) = match scheme.as_str() {
        "vless" => (Proto::Vless, "vless"),
        "trojan" => (Proto::Trojan, "trojan"),
        "hy2" | "hysteria2" => (Proto::Hysteria2, "hysteria2"), // alias birlestir
        "hysteria" => (Proto::Hysteria, "hysteria"),
        "tuic" => (Proto::Tuic, "tuic"),
        "wireguard" | "wg" => (Proto::Wireguard, "wireguard"),
        "socks" | "socks5" => (Proto::Socks, "socks"),
        "http" => (Proto::Http, "http"),
        _ => return None,
    };
    let url = Url::parse(nofrag).ok()?;
    let (host, port, canon) = generic_canonical(proto, canon_scheme, &url)?;
    Some(finish(uri, proto, host, port, canon))
}

fn finish(original: String, proto: Proto, host: String, port: u16, canonical: String) -> Item {
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let fingerprint = format!("{:x}", h.finalize());
    Item {
        original,
        proto,
        host,
        port,
        fingerprint,
        canonical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_does_not_change_identity() {
        let a = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls&sni=h.example#Ad1").unwrap();
        let b = parse_item("vless://11111111-1111-1111-1111-111111111111@h.example:443?security=tls&sni=h.example#BaskaAd").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn query_order_irrelevant() {
        let a = parse_item("vless://u@h.example:443?security=tls&sni=h.example&type=ws").unwrap();
        let b = parse_item("vless://u@h.example:443?type=ws&sni=h.example&security=tls").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn hy2_alias_unified() {
        let a = parse_item("hy2://pw@h.example:443?sni=h.example").unwrap();
        let b = parse_item("hysteria2://pw@h.example:443?sni=h.example").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.proto, Proto::Hysteria2);
    }

    #[test]
    fn ss_forms_unified() {
        // sifre ayniysa (sifre: "test"), farkli kodlamalar ayni baglantidir
        let plain = "ss://YWVzLTI1Ni1nY206dGVzdA@h.example:8388";
        let a = parse_item(plain).unwrap();
        let b = parse_item("ss://aes-256-gcm:test@h.example:8388").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn port_kept() {
        let a = parse_item("trojan://pw@h.example:443?sni=h.example").unwrap();
        assert_eq!(a.port, 443);
        let b = parse_item("trojan://pw@h.example:80?sni=h.example").unwrap();
        assert_eq!(b.port, 80);
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn vmess_ps_ignored() {
        use base64::engine::general_purpose::STANDARD as S;
        use base64::Engine as _;
        let j1 = r#"{"v":"2","add":"H.EXAMPLE","port":"443","id":"uuid-1","aid":"0","net":"ws","type":"none","host":"h.example","path":"/x","tls":"tls","ps":"Ad1"}"#;
        let j2 = r#"{"v":"2","add":"h.example","port":443,"id":"uuid-1","aid":0,"net":"ws","type":"none","host":"h.example","path":"/x","tls":"tls","ps":"Ad2"}"#;
        let a = parse_item(&format!("vmess://{}", S.encode(j1))).unwrap();
        let b = parse_item(&format!("vmess://{}", S.encode(j2))).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.port, 443);
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(parse_item("").is_none());
        assert!(parse_item("not-a-uri").is_none());
        assert!(parse_item("ftp://h:21").is_none());
        assert!(parse_item("vless://").is_none());
    }
}
