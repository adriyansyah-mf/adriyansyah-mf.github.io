---
layout: post
title: Hackback Data Exfiltration Point dari Agent Tesla Stealer
category: cybersecurity
tags: [cybersecurity,  blue team, malware analysis]
fullview: false
description: Bagaimana saya menemukan credentials FTP di balik agent tesla
---

# Hackback Data Exfiltration Point dari Agent Tesla Stealer

## Pendahuluan
Agent Tesla termasuk salah satu malware stealer yang cukup sering ditemui di berbagai insiden keamanan. Malware ini punya kemampuan mencuri berbagai macam data sensitif dari perangkat korban, seperti password yang tersimpan di browser, data dari keylogger, tangkapan layar, bahkan sampai informasi sistem.

Di tulisan ini, saya mau berbagi pengalaman waktu menganalisis salah satu kasus yang melibatkan Agent Tesla. Menariknya, dari proses analisa itu saya berhasil menemukan titik eksfiltrasi data yang mereka gunakan, termasuk akses ke server tempat data hasil curian dikirimkan.

## Latar Belakang Kasus
Hari itu berjalan seperti biasa, saya mulai aktivitas rutin dengan mengecek mail gateway. Seperti biasanya, saya berharap ada aktivitas mencurigakan yang bisa dianalisa lebih lanjut, dan ternyata beneran ada. Ada sebuah email yang terdeteksi mengandung malware.

Begitu file dicurigai sebagai malware, langkah berikutnya saya lakukan analisa untuk mencari tahu lebih dalam, khususnya untuk mengekstrak IOC atau Indicator of Compromise. Dari IOC ini, kita bisa petakan pola serangan atau minimal tau indikator apa yang harus diwaspadai di sistem lain.

Proses analisa saya mulai dengan pendekatan dynamic analysis, yaitu dengan menjalankan file tersebut di sandbox environment supaya kita bisa lihat langsung perilaku file itu tanpa mengganggu sistem produksi.



## Metodologi Analisis

### 1. Dynamic Analysis

Setelah file dijalankan di sandbox, saya posisikan diri seolah-olah jadi korban, biar semua aktivitas malware bisa termonitor dengan jelas. Salah satu hal yang penting dalam proses ini adalah memantau traffic jaringan, jadi saya capture aktivitas jaringan dalam bentuk file PCAP.

Pas pertama buka PCAP, sebagian besar traffic masih standar, belum kelihatan ada aktivitas yang terlalu mencurigakan. Tapi setelah diamati lebih jauh, akhirnya saya menemukan aktivitas yang cukup menonjol.

![PCAP File](/images/traffic-pcap.png)

Ternyata malware ini mencoba melakukan koneksi ke port 21, yang berarti mereka memanfaatkan FTP sebagai jalur eksfiltrasi data. Dari sini udah mulai kelihatan arah serangannya.

Karena penasaran, saya coba telusuri lebih jauh dengan mengakses FTP server tujuan. Dan dugaan saya terbukti, server tersebut memang digunakan untuk menyimpan data hasil curian dari korban-korban sebelumnya.
![FTP Server](/images/ftp-stealer.png)

Di dalam server itu, saya cek salah satu file yang tersimpan, dan ternyata berisi data-data sensitif seperti kredensial dan informasi lain yang berhasil dikumpulkan malware.



Ketika saya membuka salah satu file-nya adalah sebagai berikut
![File](/images/file.png)

## Penutup
Kasus ini jadi salah satu contoh yang cukup menarik gimana malware stealer seperti Agent Tesla bekerja. Mulai dari penyebaran via email, teknik eksfiltrasi menggunakan FTP, sampai akhirnya kita bisa tracing balik ke server tempat mereka menyimpan data hasil curian.

Intinya, selalu penting untuk teliti saat monitoring sistem, karena kadang hal kecil seperti email mencurigakan bisa jadi pintu masuk serangan lebih besar.

*Happy hunting! Stay safe dan selalu ikuti ethical guidelines dalam cybersecurity research.* 