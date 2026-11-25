mod config;
mod fetch;
mod output;
mod parse;
mod singbox;
mod state;
mod tcp;

use clap::Parser;
use config::Args;
use parse::{Item, Proto};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

fn proto_name(p: Proto) -> &'static str {
    p.as_str()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let now = state::now_unix();
    println!("[BILGI] barisvpn basliyor");

    // ---------- 1) INDIR ----------
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("barisvpn/0.1")
        .build()?;
    let raws: Vec<String> =
        futures::future::join_all(args.sources.iter().map(|u| fetch::fetch_text(&client, u))).await;
    let mut all_uris: Vec<String> = Vec::new();
    for (url, raw) in args.sources.iter().zip(raws.iter()) {
        if raw.is_empty() {
            continue;
        }
        let decoded = fetch::decode_if_b64(raw);
        let got = fetch::extract_uris(&decoded);
        println!("[BILGI] {url} -> {} config", got.len());
        all_uris.extend(got);
    }
    println!("[BILGI] Toplam ham: {}", all_uris.len());
    if all_uris.is_empty() {
        anyhow::bail!("hic config indirilemedi; kaynaklar erisilemez");
    }

    // ---------- 2) PARSE + BAGLANTI-BAZLI DEDUP ----------
    // Ayni #isimli farkli sunucu AYRI tutulur, farkli #isimli ayni sunucu BIRLESTIRILIR.
    let mut by_fp: HashMap<String, Arc<Item>> = HashMap::new();
    let mut proto_total: HashMap<&str, usize> = HashMap::new();
    let mut parse_fail = 0usize;
    for raw in all_uris {
        match parse::parse_item(&raw) {
            Some(it) => {
                *proto_total.entry(proto_name(it.proto)).or_default() += 1;
                by_fp
                    .entry(it.fingerprint.clone())
                    .or_insert_with(|| Arc::new(it));
            }
            None => parse_fail += 1,
        }
    }
    println!(
        "[BILGI] Parse: {} benzersiz baglanti ({} tekrar dustu, {} parse-disi)",
        by_fp.len(),
        proto_total
            .values()
            .sum::<usize>()
            .saturating_sub(by_fp.len()),
        parse_fail
    );
    let mut pt: Vec<_> = proto_total.into_iter().collect();
    pt.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, v) in &pt {
        println!("  - {k}: {v}");
    }

    // ---------- 3) HISTORY + UNIVERSE ----------
    let mut history = state::History::load(&args.history);
    println!("[BILGI] History: {} kayit", history.entries.len());

    // Universe = bu calismada gorulenler + onceki calismadan tasinanlar (gecikmeli dusurme icin).
    // Boylece tek seferlik rate-limit listedekini aninda silmez.
    let new_count = by_fp.len();
    let mut universe: HashMap<String, Arc<Item>> = by_fp;
    let mut carried = 0usize;
    for (fp, e) in history.entries.iter() {
        if universe.contains_key(fp) {
            continue;
        }
        if e.tcp_f >= args.keep_fails && e.tun_f >= args.tunnel_keep_fails {
            continue; // iki grace de tukenmis -> test slotu harcama
        }
        if carried >= args.max_history {
            break;
        }
        if let Some(it) = parse::parse_item(&e.o) {
            if it.fingerprint == *fp {
                universe.insert(fp.clone(), Arc::new(it));
                carried += 1;
            }
        }
    }
    // Not: universe buyuklugu history cap ile sinirli tutulur (prune asagida).
    let mut items: Vec<Arc<Item>> = universe.values().cloned().collect();
    // Deterministik sira: ayni profiller tekrar tekrar farkli sirada yazilmaz.
    items.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    println!(
        "[BILGI] Test universe: {} (yeni: {new_count}, history'den tasinan: {carried})",
        items.len(),
    );

    // ---------- 4) TCP TESTI ----------
    println!(
        "[BILGI] TCP testi basliyor ({} config, {} worker)...",
        items.len(),
        args.tcp_workers
    );
    let tcp_res = tcp::test_many(
        &items,
        args.tcp_workers,
        Duration::from_secs(args.tcp_timeout_secs),
        300,
    )
    .await;
    let tcp_pass: HashSet<String> = tcp_res
        .iter()
        .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
        .collect();
    println!("[BILGI] TCP: {}/{} canli", tcp_pass.len(), items.len());
    for (h, n) in tcp::host_histogram(&items, &tcp_pass).iter().take(5) {
        println!("  host yogunlugu: {h} -> {n}");
    }

    // ---------- 5) TUNEL TESTI (sing-box, tum protokoller) ----------
    let mut tunnel_ok: HashSet<String> = HashSet::new();
    if args.skip_tunnel {
        println!("[UYARI] --skip-tunnel: tunel testi atlandi");
    } else {
        match singbox::resolve_singbox(args.singbox.as_deref()) {
            None => {
                println!(
                    "[UYARI] sing-box bulunamadi (SINGBOX_PATH/--singbox). Tunel testi atlandi."
                );
                println!("        Yerel: https://github.com/SagerNet/sing-box/releases adresinden indirip SINGBOX_PATH ile ver.");
            }
            Some(sb) => {
                let cand: Vec<Arc<Item>> = items
                    .iter()
                    .filter(|it| tcp_pass.contains(&it.fingerprint))
                    .cloned()
                    .collect();
                println!("[BILGI] Destek matrisi (tunel-testine girebilirlik):");
                for (p, total, supported) in singbox::support_stats(&cand) {
                    println!("  - {p}: {supported}/{total}");
                }
                println!(
                    "[BILGI] Tunel testi basliyor ({} config, {} worker, {}s timeout)...",
                    cand.len(),
                    args.tunnel_workers,
                    args.tunnel_timeout_secs
                );
                let res = singbox::test_many(
                    &cand,
                    &sb,
                    &args.test_url,
                    &args.test_url_fallback,
                    args.tunnel_workers,
                    Duration::from_secs(args.tunnel_timeout_secs),
                    Duration::from_secs(args.boot_timeout_secs),
                )
                .await;
                let mut ok_n = 0usize;
                let mut reasons: HashMap<String, usize> = HashMap::new();
                for (fp, (ok, reason)) in &res {
                    if *ok {
                        tunnel_ok.insert(fp.clone());
                        ok_n += 1;
                    } else {
                        *reasons.entry(reason.clone()).or_default() += 1;
                    }
                }
                println!("[BILGI] Tunel: {ok_n}/{} calisiyor", cand.len());
                let mut rs: Vec<_> = reasons.into_iter().collect();
                rs.sort_by(|a, b| b.1.cmp(&a.1));
                for (r, n) in rs.iter().take(8) {
                    println!("  neden({r}): {n}");
                }
            }
        }
    }

    // ---------- 6) KATI KURAL + ASIMETRIK GRACE: super = TCP && TUNEL ----------
    // superport = super'in 80/443 alt kumesi.
    // - TCP && tunel OK -> girer.
    // - TCP OK + tunel FAIL -> GitHub-runner datacenter blogu suphesi:
    //   daha once kati-basarmissa tunnel_keep_fails kosuya kadar kalir.
    // - TCP FAIL -> olu suphesi: keep_fails kosuya kadar kalir (kisa).
    let mut super_fps: Vec<String> = Vec::new();
    for (fp, item) in universe.iter() {
        let e = history.entries.entry(fp.clone()).or_insert_with(|| {
            state::Entry::fresh(item.original.clone(), item.canonical.clone(), now)
        });
        // guncel temsilciyi koru (isim degisse bile baglanti ayni)
        if e.o != item.original {
            e.o = item.original.clone();
        }
        e.c = item.canonical.clone();
        let keep = e.observe(
            tcp_pass.contains(fp),
            tunnel_ok.contains(fp),
            args.keep_fails,
            args.tunnel_keep_fails,
            now,
            true,
        );
        if keep {
            super_fps.push(fp.clone());
        }
    }
    history.prune(args.max_history);
    history.save(&args.history);

    super_fps.sort();

    let fp_to_item: HashMap<&str, &Arc<Item>> =
        universe.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let mut super_lines: Vec<String> = Vec::new();
    let mut superport_lines: Vec<String> = Vec::new();
    for fp in &super_fps {
        let line = match fp_to_item.get(fp.as_str()) {
            Some(it) => it.original.clone(),
            None => match history.entries.get(fp) {
                Some(e) => e.o.clone(),
                None => continue,
            },
        };
        // portu history'den degil, guncel parse'tan al
        let port = fp_to_item
            .get(fp.as_str())
            .map(|it| it.port)
            .or_else(|| parse::parse_item(&line).map(|it| it.port))
            .unwrap_or(0);
        super_lines.push(line.clone());
        if Args::port_allowed(port) {
            superport_lines.push(line);
        }
    }

    output::write_lines(&args.out_super, &super_lines)?;
    output::write_lines(&args.out_superport, &superport_lines)?;
    if args.also_b64 {
        output::write_b64(&output::b64_path(&args.out_super), &super_lines)?;
        output::write_b64(&output::b64_path(&args.out_superport), &superport_lines)?;
        println!(
            "[BILGI] b64 subscriptionlar yazildi: {}, {}",
            output::b64_path(&args.out_super).display(),
            output::b64_path(&args.out_superport).display()
        );
    }
    println!(
        "[BILGI] {} yazildi -> {} config",
        args.out_super.display(),
        super_lines.len()
    );
    println!(
        "[BILGI] {} yazildi -> {} config (80/443)",
        args.out_superport.display(),
        superport_lines.len()
    );
    Ok(())
}
