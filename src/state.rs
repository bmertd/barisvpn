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
    /// Art arda basarisizlik sayisi.
    #[serde(default)]
    pub f: u32,
    /// Son basari (unix sn, 0 = henuz basari yok).
    #[serde(default)]
    pub ls: i64,
    /// Son gorulme (unix sn).
    #[serde(default)]
    pub lw: i64,
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
        let mut keys: Vec<(String, u32, i64)> = self
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.f, e.lw))
            .collect();
        // once hic basarmamis + eski olanlar gider
        keys.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)));
        let drop_n = self.entries.len() - max;
        for (k, _, _) in keys.into_iter().take(drop_n) {
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
