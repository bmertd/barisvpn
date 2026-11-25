# barisVPN

Halka açık ücretsiz VPN listelerini toplayıp **gerçekten çalışanları** ayıklayan,
sonucu hazır subscription dosyası olarak üreten Rust aracı + 3 saatte bir çalışan
GitHub Actions işi.

Eski Python scriptinin (`scripts/process_configs.py`) sıfırdan, daha mantıklı
yazılmış halidir.

## Çıktılar (tek mantık: katı kural)

| Dosya | Kural |
|---|---|
| `super.txt` | **TCP canlı VE tam tünel çalışıyor** (tüm portlar) |
| `superport.txt` | Yukarıdakilerin **sadece 80/443** alt kümesi |
| `super.b64.txt` / `superport.b64.txt` | Aynı listelerin base64 subscription hali (uygulamaya direkt import) |
| `state/history.json` | Geçmiş/grace-state (commit'lenir) |

`all_sub`, `supersub`, `splitted` gibi ara/gevşek listeler **yok** — sadece
`supersupersub` mantığı var: `super` (portsuz filtre) ve `superport` (80/443).

## Nasıl çalışıyor?

```
İndir (3 kaynak) → base64 çöz → URI ayıkla
→ bağlantı-bazlı dedup (fingerprint)
→ TCP testi → sing-box ile tam tünel testi
→ super / superport yaz + history güncelle
```

1. **Toplama:** 3 public subscription kaynağı indirilir, base64 (tek/çift kat)
   çözülür, config satırları ayıklanır.
2. **Dedup (bağlantı-bazlı, isim-bazlı DEĞİL):** Her config, `#isim` etiketi
   atılmış, sorgu parametreleri sıralanmış, host'u küçültülmüş **canonical**
   forma sokulur; `sha256(canonical)` fingerprint'i aynı olanlar tekile
   düşürülür. Yani:
   - `#Ev` ile `#Ofis` etiketli aynı sunucu → **1 kayıt**
   - `hy2://` ile `hysteria2://` aynı sunucu → **1 kayıt**
   - `ss://` base64 hali ile açık hali → **1 kayıt**
   - `vmess` içinde `ps` farklı ama sunucu aynı → **1 kayıt**
   - sorgu parametre sırası farklı → **1 kayıt**
3. **TCP testi:** `host:port`'a gerçek TCP bağlantısı (5 sn timeout, 2 deneme).
4. **Tünel testi:** Her config sing-box outbound JSON'ına çevrilir, local'de
   SOCKS açılır, `http://www.gstatic.com/generate_204` üzerinden gerçekten
   veri geçip geçmediği ölçülür. **Desteklenenler:** `vless`, `vmess`,
   `trojan`, `ss`, `hysteria2`/`hy2`, `hysteria`, `tuic`, `socks`, `http`.
   (`ssr`/`wireguard`: parse + TCP edilir ama bakımlı çekirdek desteği
   olmadığı için tünel-dışı sayılır; eski Python kodundaki gibi sessizce
   `unsupported` olup listeye sızmazlar.)
5. **Katı kural:** Listeye girmek için **hem TCP hem tünel** geçmek zorunda.

## Rate-limit koruması (GitHub runner'dan test ediliyor diye)

Runner IP'si sunucularca throttle yiyip sağlam config'leri elememek için:

- **Düşük tünel paralelliği** (varsayılan 12, TCP 64) + **host-başı bekleme**
  (TCP 300 ms, tünel 800 ms) + jitter — aynı sunucuya abanma yok.
- **Her testte 2 deneme** (TCP ve tünel ayrı ayrı).
- **Grace/history:** Bir config tek seferlik patlarsa hemen silinmez;
  `state/history.json`'da art arda başarısızlık sayılır. `--keep-fails 2`
  ile **üst üste 2 çalışmada da** başarısız olan düşer. Daha önce hiç
  başarmamış kayıtlar grace'e girmez (çöp liste şişmez).
- Çıktılar fingerprint'e göre **sıralı ve deterministik** yazılır; aynı
  profiller her çalışmada yeniden yazılıp diff şişirmez.

## Yerelde çalıştırma

```bash
# sing-box gerekli (tünel testi için):
# https://github.com/SagerNet/sing-box/releases
export SINGBOX_PATH=/usr/local/bin/sing-box

cargo run --release
# veya tünelsiz hızlı deneme:
cargo run -- --skip-tunnel --out-super /tmp/super.txt --out-superport /tmp/sp.txt
```

Seçenekler (`--help`): `--sources`, `--tcp-workers`, `--tunnel-workers`,
`--tcp-timeout-secs`, `--tunnel-timeout-secs`, `--keep-fails`,
`--max-history`, `--test-url`, `--singbox`, `--skip-tunnel`.

## Otomasyon

`.github/workflows/update.yml` → `0 */3 * * *` (3 saatte bir) + manuel
tetikleme. Rust toolchain + güncel sing-box kurar, `cargo test` koşar,
`cargo run --release` ile listeleri üretir, değiştiyse commit'leyip push'lar.

## Proje yapısı

```
src/main.rs    orkestrasyon (indir → dedup → test → yaz)
src/fetch.rs   indirme + base64 çözüm + satır ayıklama
src/parse.rs   URI parse + bağlantı-bazlı canonical fingerprint
src/tcp.rs     TCP canlılık testi + host throttle
src/singbox.rs sing-box outbound üretimi + tam tünel testi
src/state.rs   history (grace) yükleme/kaydetme/budama
src/config.rs  CLI argümanları
```
