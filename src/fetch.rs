use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE},
    Engine as _,
};

/// Desteklenen URI semalari (case-insensitive).
pub const SCHEMES: &[&str] = &[
    "vmess://",
    "vless://",
    "trojan://",
    "ss://",
    "ssr://",
    "hy2://",
    "hysteria2://",
    "hysteria://",
    "tuic://",
    "wireguard://",
    "wg://",
    "socks://",
    "socks5://",
    "http://",
];

pub async fn fetch_text(client: &reqwest::Client, url: &str) -> String {
    match client.get(url).send().await {
        Ok(r) => match r.error_for_status() {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(e) => {
                eprintln!("[HATA] {url} -> {e}");
                String::new()
            }
        },
        Err(e) => {
            eprintln!("[HATA] {url} -> {e}");
            String::new()
        }
    }
}

fn pad(s: &str) -> String {
    let mut o = s.to_string();
    while o.len() % 4 != 0 {
        o.push('=');
    }
    o
}

/// Tek kat base64 coz (standart + urlsafe). Basarisizsa None.
pub fn try_b64(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let std_s: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    // urlsafe -> standart donusumu dene
    let norm = std_s.replace('-', "+").replace('_', "/");
    for cand in [pad(&norm), pad(&std_s)] {
        if let Ok(b) = STANDARD.decode(&cand) {
            if let Ok(txt) = String::from_utf8(b) {
                return Some(txt);
            }
        }
    }
    // ham urlsafe dene
    let nospace: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(b) = URL_SAFE.decode(pad(&nospace)) {
        if let Ok(txt) = String::from_utf8(b) {
            return Some(txt);
        }
    }
    None
}

fn looks_like_b64(s: &str) -> bool {
    s.len() > 40
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
        })
}

/// Subscription govdesi base64'lu ise coz (cift kat dahil, ozyinelemeli).
pub fn decode_if_b64(text: &str) -> String {
    let t = text.trim();
    if t.is_empty() {
        return String::new();
    }
    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if !looks_like_b64(&compact) {
        return text.to_string();
    }
    let mut cur = match try_b64(&compact) {
        Some(d) => d,
        None => return text.to_string(),
    };
    // tek kat cozum anlamsizsa (:// yok) ama sonuc yine base64 gorunuyorsa derine in
    for _ in 0..2 {
        if cur.contains("://") {
            break;
        }
        let c: String = cur.chars().filter(|c| !c.is_whitespace()).collect();
        if !looks_like_b64(&c) {
            break;
        }
        match try_b64(&c) {
            Some(next) if next != cur => cur = next,
            _ => break,
        }
    }
    if cur.contains("://") || cur.contains('\n') {
        cur
    } else {
        text.to_string()
    }
}

/// Metinden config satirlarini ayikla.
pub fn extract_uris(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // satir basi bosluk + scheme; satirda bosluktan sonrasini at
        let token = line.split_whitespace().next().unwrap_or("");
        let low = token.to_ascii_lowercase();
        if SCHEMES.iter().any(|s| low.starts_with(s)) {
            out.push(token.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        let raw = "vless://uuid@host:443?security=tls#isim\ntrojan://pw@h2:443";
        let enc = STANDARD.encode(raw);
        assert_eq!(decode_if_b64(&enc).trim(), raw);
    }

    #[test]
    fn double_b64() {
        // gercek subscription: cok satirli; ilk cozumde newline icerir
        let raw = (0..30)
            .map(|i| format!("vless://user{i}@host{i}.example:443?security=tls"))
            .collect::<Vec<_>>()
            .join("\n");
        let once = STANDARD.encode(&raw);
        let twice = STANDARD.encode(&once);
        assert!(decode_if_b64(&twice).contains("vless://"));
    }

    #[test]
    fn plain_passthrough() {
        let raw = "vless://a@b:443#x\nss://abc@h:8388";
        assert_eq!(decode_if_b64(raw), raw);
    }

    #[test]
    fn extract_basic() {
        let t = "# yorum\nvless://a@b:443#ad \n  trojan://x@y:443\nnot-a-config\nHTTP://u@h:80";
        let v = extract_uris(t);
        assert_eq!(v.len(), 3);
    }
}
