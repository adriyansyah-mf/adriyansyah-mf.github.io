---
layout: post
title: Analisa loader Malware InfoStealer
category: cybersecurity
tags: [cybersecurity,wazuh,blue team,wazuh]
fullview: false
description : Analisa loader Malware InfoStealer
---
# Reverse Engineer "ChainExecutor": Loader MSI Multi Stage yang Mencuri Kunci App-Bound Chrome

TLP:CLEAR · Analisis statis, Oktober 2026 · IOC dan YARA rule ada di akhir tulisan

---

## TL;DR

- Awal Oktober 2026 kami menangani infeksi di sebuah endpoint Windows. Malware masuk sebagai paket MSI bernama acak yang di-install dari `%TEMP%`, setelah korban membuka `cmd` lewat Win+R dan menjalankan sesuatu di sana.
- Payload dibungkus enam stage: VBScript custom action → PowerShell stager → PowerShell reflective loader → crypter stub x64 "ChainExecutor" (AES-256-CBC via CryptoAPI) → shellcode PE loader (AES-256-CBC lagi) → loader/stealer x64.
- Stealer di stage terakhir bicara ke C2 `https://unalively.com/nfront.php` dan `/nback.php`. Ia mem-bypass Chrome App-Bound Encryption lewat COM `IElevator` milik `elevation_service` Chrome, dan bisa menerima task lanjutan (EXE, MSI, PowerShell).
- Domain C2 didaftarkan 4 hari sebelum infeksi, payload terakhir di-compile 3 hari sebelumnya. Waktu tulisan ini dibuat, kami tidak menemukan publikasi atau hit publik untuk hash, string, maupun domainnya.
- Windows Defender tidak mengeluarkan alert. Yang menangkap adalah PowerShell Script Block Logging (Event ID 4104).

Semua stage kami buka secara statis, tanpa menjalankan sample. Key, IV, dan algoritmanya kami tulis lengkap supaya hasilnya bisa direproduksi.

---

## Infection chain

```
Win+R "cmd"  ──►  %TEMP%\o.msi  ──►  msiexec (product & publisher bernama acak)
   │
   ├─ [1] VBScript custom action       encoding pasangan "hi.lo" polimorfik + Execute
   │       tulis %TEMP%\<0-999999>.ps1 dari Binary stream → jalankan hidden → hapus
   ├─ [2] PowerShell stager            pasangan angka → UTF-8 → runspace baru
   ├─ [3] PowerShell reflective loader baca Binary stream MSI via msi.dll, de-interleave
   ├─ [4] Stub "ChainExecutor" (PE64)  AES-256-CBC (CryptoAPI) + byte reverse
   ├─ [5] Shellcode PE loader          AES-256-CBC + byte reverse
   └─ [6] Loader/stealer (PE64)        C2 HTTPS · Chrome IElevator · process injection
```

Di kasus ini chain-nya jalan empat kali dalam satu hari, dengan empat MSI berbeda. Tiap MSI sekitar 2,2 MB, dan hash, product name, publisher, serta nama stream-nya beda semua. Payload hasil decode dari keempat MSI identik, jadi IOC yang stabil adalah hash stage 4, 5, dan 6.

Initial vector-nya (instruksi yang membuat korban menjalankan perintah di `cmd`) tidak bisa kami rekonstruksi karena USN journal sudah tertimpa dan history browser bersih. Polanya mirip kampanye ClickFix atau panduan "fix" palsu, tapi itu belum bisa kami pastikan.

---

## Stage 1: VBScript custom action

Setiap MSI punya tiga entry di tabel `Binary`: VBScript, PowerShell stager, dan blob payload sekitar 2,14 MB. Nama stream diacak per build (contoh: `SPelDCIH`, `LMmrOyGSr`, `oZdEJ7FIE`).

VBScript menyimpan kodenya sebagai pasangan angka `hi.lo`, dirakit ulang jadi `Chr(hi*16+lo)` lalu dijalankan dengan `Execute`. Encoding-nya polimorfik: separator bisa `;` atau `,`, urutan `hi`/`lo` bisa ditukar, dan fungsinya bisa `Chr` atau `ChrW`. Setelah di-decode:

```vbscript
msiPath = Session.Property("OriginalDatabase")
' simpan msiPath ke environment variable bernama acak
' tulis Binary stream stager ke %TEMP%\<Int(Rnd*999999)>.ps1 (ADODB.Stream)
WScript.Shell.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <ps1> <msi>", 0, True
fso.DeleteFile <ps1>
```

## Stage 2–3: PowerShell stager dan reflective loader

Stager men-decode script berikutnya dari pasangan angka `d.d` (UTF-8), lalu menjalankannya di runspace baru:

```powershell
[powershell]::Create().AddScript($decoded).AddArgument($args).Invoke()
```

Script di dalam runspace inilah yang terekam di Event ID 4104. Loader-nya:

- membangun dynamic assembly di memory (`DefineDynamicAssembly` / `DefinePInvokeMethod`) untuk P/Invoke ke `kernel32` dan `msi.dll`, tanpa `Add-Type` dan tanpa menulis ke disk;
- membaca blob dari MSI-nya sendiri dengan ``SELECT `Data` FROM `Binary` WHERE `Name`='<stream>'`` lewat `MsiOpenDatabase` → `MsiDatabaseOpenView` → `MsiRecordReadStream`;
- men-deobfuscate blob tanpa kriptografi: byte 0–2 adalah stride, offset, dan flag reverse, lalu data diambil dari `blob[4 + i*stride + offset]`;
- melakukan manual PE mapping (relocation, import via `LoadLibraryA`/`GetProcAddress`, `VirtualProtect` RWX) lalu memanggil entry point dengan `CreateThread`. Untuk payload .NET, jalurnya `[Reflection.Assembly]::Load`.

Nama fungsi dan variabel diacak tiap eksekusi, dan tidak ada URL atau base64. AMSI hanya melihat kode plumbing generik.

## Stage 4: crypter stub "ChainExecutor"

| | |
|---|---|
| SHA256 | `fe9cabe1ff60a8e9b11b708a4ec182eee95c634e9ab723cca6671e03ba1e9b43` |
| Type | PE32+ x64 GUI, toolchain MinGW, 1.071.104 byte |
| Timestamp | 2026-03-29 20:04:33 UTC |
| Imphash | `241b6302ab625ed2e79213b6b4dfdeb2` |
| Version info (palsu) | Ganttchain Technologies / Advanced Routine Executor Tool / chainexecutor 6.43.49.3262 |

Section `.rsrc` diisi 20 bitmap filler untuk menurunkan entropy file secara keseluruhan, sementara `.rdata` menyimpan blob dengan entropy 8,0. Import-nya minim: `VirtualAlloc`, `VirtualProtect`, dan API Threadpool Work.

`main()` sudah di-control-flow-flatten dan disisipi junk instruction (`xchg r14, r14`, `lea rdi, [rdi]`, konstanta `movabs` yang tidak dipakai). Nilai flag disamarkan dengan XOR `0x63D70277`. Setelah dibersihkan, alurnya begini:

```c
ctx = VirtualAlloc(NULL, 0x85AF0, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
ctx->size  = 0x85AA0;
ctx->flags = ENCRYPTED(0x2000) | REVERSE(0x20000) | RWX(0x40000000);
memcpy(ctx->key, rdata_0x140092B50, 32);   // AES-256 key
memcpy(ctx->iv,  rdata_0x140092B40, 16);   // IV
memcpy(ctx->data, rdata_0x14000D0A0, 0x85AA0);
out = decrypt(ctx);                         // lihat di bawah
SubmitThreadpoolWork(CreateThreadpoolWork(callback /* jalankan out */, out, NULL));
```

Decrypt-nya memakai Windows CryptoAPI yang di-resolve dinamis:

```
CryptAcquireContext(..., PROV_RSA_AES (0x18), CRYPT_VERIFYCONTEXT)
CryptImportKey(PLAINTEXTKEYBLOB { bType=8, bVersion=2, aiKeyAlg=CALG_AES_256 (0x6610), len=32, key })
CryptSetKeyParam(KP_IV, iv)
CryptDecrypt(Final=TRUE)            → AES-256-CBC, padding PKCS#7
reverse(output)                      → shellcode stage 5
```

| Parameter | Value |
|---|---|
| Key | `a52b1e9413883cf34e82750f2df6686dd9e4f76954befd1a4f89a693964ffde0` |
| IV | `2a0a34e6152c5f24a05126d81e5727d5` |

Hasil decrypt dijalankan lewat threadpool work callback, bukan `CreateThread`. Sensor yang hanya memantau thread creation tidak akan melihatnya.

## Stage 5: shellcode PE loader

| | |
|---|---|
| SHA256 | `b985ef24558d55cabaa9bcf4c154bc89fb3fdf92f3e5fe8ef71c4ab61dc71c9c` |
| Size | 547.476 byte |

Shellcode dibuka dengan `E8 58 56 07 00`, sebuah `call` yang jump melewati struktur data, lalu `pop rcx` untuk mengambil pointer ke struktur itu. Sekilas mirip Donut, tapi `donut-decryptor` tidak mengenalinya. Struktur datanya sama persis dengan context milik stub:

```
+0x00 u32  size          (0x75610)
+0x04 u32  flags         (1 = AES, 2 = reverse, 4 = RWX)
+0x18 u8[32] AES key
+0x38 u8[16] IV
+0x48 ...  ciphertext
```

Sebelum decrypt, shellcode menjalankan dua anti-analysis check dan exit diam-diam kalau salah satunya kena. Setelah AES-256-CBC dan byte reverse, PE stage 6 di-map manual (alokasi sebesar `SizeOfImage`, relocation, import) lalu dijalankan. Format context yang sama di stage 4 dan 5 menunjukkan crypter yang sama dipakai dua kali secara berlapis.

## Stage 6: loader/stealer

| | |
|---|---|
| SHA256 | `d4b9abbba8eea16621fc269c37a48657616c9e79633cda3e05ae0ddd67687013` |
| Type | PE32+ x64, MSVC, 480.768 byte |
| Timestamp | 2026-10-06 16:09:44 UTC |
| Imphash | `a3beeb86b2d4a4a9c89d5ff3fe8bc4e0` |

### Proteksi

- 228 import `kernel32` palsu (`SetFirmwareEnvironmentVariableW`, `CreateHardLinkTransactedW`, `EnumCalendarInfoExW`, dan lain-lain), ditambah blok junk API call yang dijaga perbandingan yang tidak mungkin true, misalnya `if (&local == 0x11111)` atau `if (arg == 0x111)`. Tujuannya membingungkan emulator dan heuristik berbasis import. API yang benar-benar dipakai di-resolve ke sebuah function table global.
- Stack string untuk nama DLL, API, dan path.
- String table RC4 dengan format `u32 count`, lalu `count × (u32 type, u32 len)`, lalu data. Field bertipe 4 di-decrypt RC4 dengan key 16 byte yang dioper di setiap pemanggilan.
- Cipher Feistel custom 48 round untuk shellcode yang di-embed:

```python
def feistel48_decrypt(block_l, block_r, key):      # key = 4 x u32
    for r in range(47, -1, -1):
        f = (((block_l << 6) ^ (block_l >> 8)) + block_l) & 0xFFFFFFFF
        block_r = (block_r - ((f + key[r % 4] + r) & 0xFFFFFFFF)) & 0xFFFFFFFF
        block_l, block_r = block_r, block_l
    return block_l, block_r
```

### Config (hasil decrypt string table RC4)

| Field | Value |
|---|---|
| Host C2 | `unalively.com` |
| Endpoint | `nfront.php`, `nback.php` |
| Format URL | `https://%s/%s`, `https://%s/%s?a=%s` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Vivaldi/5.3.2679.68` |
| Header | `Content-Type: application/x-www-form-urlencoded` |
| Task interpreter | `powershell` |
| RC4 key request body | `10dda87d124c6c60368b7b814dad0279c3c7f03e86d58df8d9458523b24ea1` (31 byte) |

String table kedua berisi target di Chrome: `\Google\Chrome\User Data\Local State`, `os_crypt`, `encrypted_key`, dan `\Google\Chrome\Application\chrome.exe`. Ada juga nama file staging `Svie24xHm5.png` dan `jaw9Bytr4W.png`, serta security descriptor `D:(A;;GA;;;WD)` yang memberi full access ke Everyone.

### Bypass Chrome App-Bound Encryption

Sejak Chrome 127, key yang melindungi cookie dan password terikat ke aplikasi Chrome lewat service `elevation_service`. Stage 6 membawa shellcode yang dienkripsi Feistel (key `01579a9a8e53e206465e9fc8745625b2`, 6.640 byte). Setelah di-decrypt, isinya:

```
E9 C0 02 00 00 ...                     ; jmp ke kode
"APPB"                                 ; marker
E0 60 88 70 41 F6 11 46 88 95 7D 86 7D D3 67 5B   ; CLSID {708860E0-F641-4611-8895-7D867DD3675B}  Chrome Elevator
CF BE 3A 46 0D 41 7F 40 8A F5 0D F3 5A 00 5C C8   ; IID   {463ABECF-410D-407F-8AF5-0DF35A005CC8}  IElevator
"\\.\pipe\"                            ; back-channel ke parent process
"0123456789abcdef"                     ; hex encoding hasil
```

Malware membaca `Local State` (object `os_crypt`, key terenkripsi), meng-inject shellcode ini ke context Chrome, lalu memanggil `IElevator::DecryptData`. Key hasil decrypt dikirim balik lewat named pipe (`PIPE_ACCESS_INBOUND`, `PIPE_TYPE_MESSAGE`). Dengan key itu, semua cookie dan password Chrome bisa di-decrypt offline.

Jejak forensiknya: `elevation_service.exe` jalan di detik yang sama dengan aktivitas malware.

### Capability lain

| Capability | Bukti | Confidence |
|---|---|---|
| C2 HTTPS POST (WinHTTP) | Config RC4; wrapper WinHTTP menerima host/path dari config | Tinggi |
| Bypass ABE Chrome | Shellcode IElevator hasil decrypt, string `Local State`/`os_crypt` | Tinggi |
| Injection/hollowing ke `csc.exe`, `ilasm.exe`, `explorer.exe`, `RuntimeBroker.exe` | Stack string path `Framework64\v4.0.30319\csc.exe`/`ilasm.exe`; di Prefetch, csc/ilasm jalan bersamaan dengan infeksi tanpa ada aktivitas build .NET | Sedang–tinggi |
| Menjalankan task EXE/MSI/PowerShell | String `open`, `msiexec`, `.msi`, `.exe`, `powershell` | Sedang–tinggi |
| Bypass AMSI | `LdrLoadDll` + `\System32\Amsi.dll` + `AmsiScanBuffer`/`AmsiScanString` | Sedang–tinggi |
| Persistence `RunOnce` | Stack string di routine injection `explorer.exe` | Sedang |
| Host fingerprint | `Windows %d.%d.%d`, format GUID `%08lX-%04hX-...` | Sedang |

Catatan buat analis: `csc.exe` dan `ilasm.exe` yang muncul di Prefetch bukan tanda compile .NET on-the-fly. Keduanya hanya dipakai sebagai host injection. Kalau csc/ilasm, `elevation_service.exe`, dan `msiexec` dari `%TEMP%` muncul dalam rentang beberapa detik, kemungkinan besar Anda sedang melihat malware ini atau sesuatu yang sangat mirip.

---

## Infrastruktur

| Atribut | Value |
|---|---|
| Domain | `unalively.com` |
| Registrasi | 2026-10-05 18:16:08 UTC |
| Registrar | NICENIC INTERNATIONAL GROUP CO., LIMITED |
| Nameserver | `anuj.ns.cloudflare.com`, `macy.ns.cloudflare.com` |
| A record (12 Okt 2026) | tidak ada |

Domain didaftarkan 5 Oktober, stage 6 di-compile 6 Oktober, infeksi terjadi 9 Oktober. Stub ChainExecutor jauh lebih tua (Maret 2026). Ini mengarah ke crypter yang dijual atau dipakai ulang sebagai layanan, dibungkuskan ke payload baru.

## Atribusi

Kami tidak mengatribusikan sample ini ke family tertentu. Endpoint `nfront.php`/`nback.php`, nama ChainExecutor/Ganttchain, dan hash-hash di atas tidak kami temukan di sumber publik saat analisis. Kombinasi capability-nya (loader dengan tasking, bypass ABE via IElevator, injection ke binary .NET Framework) mirip dengan stealer/loader yang beredar sepanjang 2025–2026. Kalau Anda pernah melihat artefak yang sama, kami ingin tahu korelasinya.

---

## Kenapa lolos dari antivirus

Tidak ada executable di disk: payload tersimpan di stream MSI dalam keadaan ter-interleave dan dibalik. Setiap build MSI polimorfik, jadi hash, product name, nama stream, nama variabel script, dan parameter encoding selalu berubah. Payload melewati enam stage obfuscation dan encryption, hanya hidup di memory, dan file `.ps1`-nya dihapus setelah jalan.

Eksekusinya juga menghindari API yang biasa diawasi: P/Invoke dinamis, manual PE mapping, threadpool callback, dan injection ke binary Microsoft yang signed. Stage 6 menambah anti-emulation lewat ratusan import palsu dan mematikan AMSI. Terakhir, semua build-nya baru, sehingga hash dan domain belum punya reputasi apa pun.

## Deteksi dan mitigasi

**Telemetry yang terbukti menangkap**

- PowerShell Script Block Logging (4104), dengan alert untuk kombinasi `MsiRecordReadStream` + `VirtualAlloc` + `CreateThread`/`Assembly]::Load`, atau `DefineDynamicAssembly` + `DefinePInvokeMethod`.
- MsiInstaller di Application log (EID 1033/11707), dengan alert untuk product berpola nama/publisher acak atau install source `%TEMP%`. Paling efektif kalau Anda punya whitelist aplikasi.

**Hunting**

- Process: `msiexec.exe` → `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File %TEMP%\<angka>.ps1 <path>.msi`.
- `csc.exe` / `ilasm.exe` (Framework64) dengan parent selain Visual Studio, MSBuild, atau devenv.
- `elevation_service.exe` yang aktif di luar update Chrome, berdekatan dengan process non-Chrome yang mencurigakan.
- DNS/proxy: `unalively.com`, dan User-Agent Vivaldi 5.3 / Chrome 114. UA versi ini sudah sangat usang di 2026, jadi gampang di-filter.
- Memory scan dengan YARA `ChainExecutor_Stage6_Memory_Strings`.

**Mitigasi**

- Kalau terinfeksi, revoke semua web session yang pernah login di browser korban. Session cookie bisa dipakai login tanpa password maupun MFA, jadi ganti password saja tidak cukup. Setelah itu rotasi credential dari perangkat yang bersih, lalu reinstall OS, karena C2 bisa saja sudah mengirim payload lanjutan.
- Jangan pakai akun administrator untuk kerja sehari-hari. Di perangkat dengan akses privileged, pertimbangkan Chrome Enterprise policy untuk mematikan password saving.
- Ingatkan user: jangan paste atau ketik perintah ke Win+R, `cmd`, atau PowerShell karena disuruh sebuah situs, chat, atau panduan "fix".

---

## MITRE ATT&CK mapping

| Technique | Implementasi |
|---|---|
| T1204 User Execution | Korban menjalankan perintah di `cmd` |
| T1218.007 Msiexec | Payload di-install sebagai MSI |
| T1059.005 VBScript · T1059.001 PowerShell | Custom action dan loader |
| T1027 / T1027.009 Obfuscated Files · Embedded Payloads | Encoding pasangan angka; blob di stream MSI |
| T1140 Deobfuscate/Decode | De-interleave, AES-256-CBC, RC4, Feistel |
| T1620 Reflective Code Loading | Manual PE mapping dari PowerShell dan shellcode |
| T1070.004 File Deletion | `.ps1` dihapus |
| T1055 / T1055.012 Process Injection · Process Hollowing | csc, ilasm, explorer, RuntimeBroker |
| T1562.001 Impair Defenses | Patch AMSI |
| T1547.001 Registry Run Keys | `RunOnce` |
| T1559.001 Component Object Model | Chrome `IElevator` |
| T1555.003 Credentials from Web Browsers · T1539 Steal Web Session Cookie | Password dan cookie Chrome |
| T1082 System Information Discovery | Versi Windows, host ID |
| T1071.001 Web Protocols · T1573.001 Symmetric Cryptography | HTTPS POST, body RC4 |
| T1105 Ingress Tool Transfer | Task EXE/MSI/PowerShell |

---

## Indicators of Compromise

**Network**

```
unalively.com
hxxps://unalively[.]com/nfront.php
hxxps://unalively[.]com/nback.php
UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Vivaldi/5.3.2679.68
```

**File (SHA256)**

```
fe9cabe1ff60a8e9b11b708a4ec182eee95c634e9ab723cca6671e03ba1e9b43  stage 4 stub "ChainExecutor" (stabil)
b985ef24558d55cabaa9bcf4c154bc89fb3fdf92f3e5fe8ef71c4ab61dc71c9c  stage 5 shellcode (memory)
d4b9abbba8eea16621fc269c37a48657616c9e79633cda3e05ae0ddd67687013  stage 6 loader/stealer (memory)
c318d3e2460fe620db1b618a50067336ec5af3657f3e15fe6b07654cfaed236d  shellcode IElevator (memory)
651d76e1a1e36b273fa5cf9226daca09faf117d55a1dc3649540023ba5c35931  shellcode injector (memory)
6dfca1e4841856bf314a306e6f03b922cef0f23907b834f8c3db409588a1fcc6  MSI
5b9d720da5ebb5b1e55a189d18523d3e06f7339ffe677cf5adbe902d20825236  MSI
933a60d99218e61152f8d1373d818757ad8229a184c82c58a7649bc9848fd2f8  MSI
94dbdbab9fd504ada039c29f1e597bcf5dfbebe7e6cb3b70653fd71a2f069c91  MSI
```

**Imphash**: `241b6302ab625ed2e79213b6b4dfdeb2` (stage 4), `a3beeb86b2d4a4a9c89d5ff3fe8bc4e0` (stage 6)

**Host**: `%TEMP%\o.msi`, `%TEMP%\<0-999999>.ps1` (dihapus), `Svie24xHm5.png`, `jaw9Bytr4W.png`, product MSI dengan nama/publisher acak (contoh: `y6yDW3Xvq pqMTzmDk` / `YMT3P1rXLf6G`).

Daftar lengkap (34 entry) ada di `iocs.csv`.

## YARA

`chainexecutor_stealer.yar` berisi 8 rule yang mencakup semua stage: MSI dan VBScript custom action, PowerShell stager, reflective loader (juga cocok untuk teks Event 4104), stub ChainExecutor, blob di MSI, shellcode stage 5, PE stage 6, dan string stage 6 di memory. Dalam pengujian kami, setiap rule match ke sample targetnya, tanpa false positive (0 dari 1.530 file benign untuk rule stage 1–4, dan 0 dari 14.388 file sistem untuk rule stage 5–6).

Contoh rule untuk memory scan:

```yara
rule ChainExecutor_Stage6_Memory_Strings
{
    strings:
        $c2 = "unalively.com" ascii wide
        $p1 = "nfront.php" ascii wide
        $p2 = "nback.php" ascii wide
        $f1 = "Svie24xHm5.png" ascii wide
        $f2 = "jaw9Bytr4W.png" ascii wide
        $ua = "Chrome/114.0.0.0 Safari/537.36 Vivaldi/5.3.2679.68" ascii wide
        // "APPB" + Chrome Elevator CLSID {708860E0-F641-4611-8895-7D867DD3675B}
        $abe = { 41 50 50 42 E0 60 88 70 41 F6 11 46 88 95 7D 86 7D D3 67 5B }
    condition:
        $abe or $c2 or 2 of ($p*, $f*, $ua)
}
```

---

*Seluruh analisis ini statis. Capability dengan confidence "sedang" disimpulkan dari string dan korelasi forensik, belum dari penelusuran kode penuh.*
