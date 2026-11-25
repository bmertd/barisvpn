use clap::Parser;
use std::path::PathBuf;

/// barisvpn: halka acik VPN listelerini toplayip TCP + tam tunel testiyle
/// dogrulayan ve `super` / `superport` ciktilari ureten arac.
#[derive(Parser, Debug, Clone)]
#[command(name = "barisvpn", version)]
pub struct Args {
    /// Kaynak subscription URL'leri (virgulle ayrili).
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt,https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt,https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt"
    )]
    pub sources: Vec<String>,

    /// Tum portlar: TCP + tunel testini GECENLER (katı kural).
    #[arg(long, default_value = "super.txt")]
    pub out_super: PathBuf,

    /// Sadece 80/443: TCP + tunel testini GECENLER (katı kural).
    #[arg(long, default_value = "superport.txt")]
    pub out_superport: PathBuf,

    /// Her .txt'nin base64 subscription kopyasini da yaz (.b64.txt).
    #[arg(long, default_value_t = true)]
    pub also_b64: bool,

    /// Gecmis / grace-state dosyasi (commit'lenir).
    #[arg(long, default_value = "state/history.json")]
    pub history: PathBuf,

    /// Art arda kac basarisizliktan sonra listeden dusur (rate-limit korumasi).
    /// 2 = tek seferlik flake/rate-limit elemez, 2. kez de patlarsa dusurur.
    #[arg(long, default_value_t = 2)]
    pub keep_fails: u32,

    /// History'de tutulacak max kayit (LRU budama).
    #[arg(long, default_value_t = 20000)]
    pub max_history: usize,

    /// TCP test paralelligi.
    #[arg(long, default_value_t = 64)]
    pub tcp_workers: usize,

    /// Tunel test paralelligi. DUSUK tut: rate-limit + runner yuku icin.
    #[arg(long, default_value_t = 12)]
    pub tunnel_workers: usize,

    /// TCP baglanti timeout (sn).
    #[arg(long, default_value_t = 5)]
    pub tcp_timeout_secs: u64,

    /// Tunel uzerinden HTTP test timeout (sn).
    #[arg(long, default_value_t = 12)]
    pub tunnel_timeout_secs: u64,

    /// sing-box'un SOCKS portunu acmasi icin beklenecek sure (sn).
    #[arg(long, default_value_t = 4)]
    pub boot_timeout_secs: u64,

    /// Tunel testi hedefi.
    #[arg(long, default_value = "http://www.gstatic.com/generate_204")]
    pub test_url: String,

    /// sing-box binary yolu. Verilmezse SINGBOX_PATH env'i, sonra PATH aranir.
    #[arg(long)]
    pub singbox: Option<PathBuf>,

    /// Tunel testini atla (sadece TCP + parse; debug/cevrimiçi olmayan ortam).
    #[arg(long, default_value_t = false)]
    pub skip_tunnel: bool,
}

impl Args {
    /// superport kurali: sadece dunya-standardı web portlari.
    pub fn port_allowed(port: u16) -> bool {
        port == 80 || port == 443
    }
}
