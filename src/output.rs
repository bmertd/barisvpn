use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::io;
use std::path::Path;

pub fn write_lines(path: &Path, lines: &[String]) -> io::Result<()> {
    if let Some(p) = path.parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    let mut s = lines.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    // atomik yaz: ayni profillerin yarisinin yazilmasini engelle
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, s)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// V2Ray istemcilerinin dogrudan ice aktarabilecegi base64 subscription.
pub fn write_b64(path: &Path, lines: &[String]) -> io::Result<()> {
    let mut s = lines.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    let enc = STANDARD.encode(s.as_bytes());
    write_lines(path, &[enc])
}

/// `super.txt` icin b64 dosya adini turet: super.txt -> super.b64.txt
pub fn b64_path(path: &Path) -> std::path::PathBuf {
    match path.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => path.with_file_name(format!("{stem}.b64.txt")),
        None => path.with_extension("b64.txt"),
    }
}
