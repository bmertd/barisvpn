use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Ciktiya yazilacak temsilci URI (ilk gorulen ham hali).
    #[serde(default)]
    pub o: String,
    /// Canonical baglanti kimligi (debug/dogrulama icin).
    #[serde(default)]
    pub c: String,
    /// Art arda TCP basarisizligi (olu sunucu sinyali -> kisa tolerans).
    #[serde(default)]
    pub tcp_f: u32,
    /// Art arda tunel basarisizligi (TCP canliysa datacenter-blok suphesi -> uzun tolerans).
    #[serde(default)]
    pub tun_f: u32,
    /// Son kati-basari (TCP && tunel) unix sn, 0 = henuz basari yok.
    #[serde(default)]
    pub ls: i64,
    /// Son gorulme (unix sn).
    #[serde(default)]
    pub lw: i64,
}

impl Entry {
    pub fn fresh(original: String, canonical: String, now: i64) -> Self {
        Self {
            o: original,
            c: canonical,
            tcp_f: 0,
            tun_f: 0,
            ls: 0,
            lw: now,
        }
    }

    /// Bir kosunun sonucunu isle. Donus: bu kayit super ciktisina girmeli mi?
    ///
    /// - TCP && tunel OK -> girer, sayaçlar sifirlanir.
    /// - TCP OK + tunel FAIL -> datacenter-blok suphesi: `keep_tun` kosuya
    ///   kadar listede kalir (uzun grace).
    /// - TCP FAIL -> sunucu olu suphesi: `keep_tcp` kosuya kadar kalir (kisa grace).
    /// - Hic kati-basari gormemis (ls == 0) kayit grace'e girmez.
    pub fn observe(
        &mut self,
        tcp_ok: bool,
        tun_ok: bool,
        keep_tcp: u32,
        keep_tun: u32,
        now: i64,
        in_universe: bool,
    ) -> bool {
        self.lw = now;
        if tcp_ok && tun_ok {
            self.tcp_f = 0;
            self.tun_f = 0;
            self.ls = now;
            return in_universe;
        }
        if tcp_ok {
            self.tcp_f = 0;
            self.tun_f = self.tun_f.saturating_add(1);
        } else {
            self.tcp_f = self.tcp_f.saturating_add(1);
            self.tun_f = self.tun_f.saturating_add(1);
        }
        if self.ls == 0 || !in_universe {
            return false;
        }
        if tcp_ok {
            self.tun_f < keep_tun
        } else {
            self.tcp_f < keep_tcp
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: HashMap<String, Entry>,
}

fn default_version() -> u32 {
    1
}

impl Default for History {
    fn default() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
        }
    }
}

impl History {
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) {
        if let Some(p) = path.parent() {
            if !p.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(p);
            }
        }
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, t).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Boyut sinirini asarsa en yasli / en basarisiz kayitlari buda.
    pub fn prune(&mut self, max: usize) {
        if self.entries.len() <= max {
            return;
        }
        let mut keys: Vec<(String, u32, u32, i64)> = self
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.tcp_f + e.tun_f, e.tcp_f, e.lw))
            .collect();
        // once hic basarmamis + eski olanlar gider
        keys.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.3.cmp(&b.3)));
        let drop_n = self.entries.len() - max;
        for (k, _, _, _) in keys.into_iter().take(drop_n) {
            self.entries.remove(&k);
        }
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e() -> Entry {
        Entry::fresh("vless://u@h:443".into(), "vless://u@h:443".into(), 1000)
    }

    #[test]
    fn strict_pass_resets_and_includes() {
        let mut x = e();
        assert!(x.observe(true, true, 2, 10, 1001, true));
        assert_eq!((x.tcp_f, x.tun_f), (0, 0));
        assert_eq!(x.ls, 1001);
    }

    #[test]
    fn never_verified_gets_no_grace() {
        let mut x = e();
        assert!(!x.observe(true, false, 2, 10, 1001, true)); // TCP ok, tunel yok, ama hic basarmamis
        assert!(!x.observe(false, false, 2, 10, 1001, true));
    }

    #[test]
    fn tunnel_fail_gets_long_grace_after_proven() {
        let mut x = e();
        assert!(x.observe(true, true, 2, 3, 1000, true));
        // keep_tun=3: 2 kosu kalir, 3. dusurulur (datacenter-blok suphesi)
        assert!(x.observe(true, false, 2, 3, 1001, true));
        assert!(x.observe(true, false, 2, 3, 1002, true));
        assert!(!x.observe(true, false, 2, 3, 1003, true));
    }

    #[test]
    fn tcp_fail_gets_short_grace() {
        let mut x = e();
        assert!(x.observe(true, true, 2, 10, 1000, true));
        assert!(x.observe(false, false, 2, 10, 1001, true)); // 1. fail: kalir
        assert!(!x.observe(false, false, 2, 10, 1002, true)); // 2. fail: duser
    }

    #[test]
    fn recovery_resets_counters() {
        let mut x = e();
        assert!(x.observe(true, true, 2, 10, 1000, true));
        assert!(x.observe(true, false, 2, 10, 1001, true));
        assert_eq!(x.tun_f, 1);
        assert!(x.observe(true, true, 2, 10, 1002, true));
        assert_eq!((x.tcp_f, x.tun_f), (0, 0));
    }

    #[test]
    fn outside_universe_never_included() {
        let mut x = e();
        assert!(x.observe(true, true, 2, 10, 1000, true));
        assert!(!x.observe(true, true, 2, 10, 1001, false));
    }
}
