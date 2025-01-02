---
layout: post
title: Automasi Deteksi Malware dan Blokir IP Terpusat dengan Platform Custom
category: cybersecurity
tags: [cybersecurity,wazuh,n8n,soar]
fullview: false
description : Merancang sistem centralized untuk mengelola firewall di berbagai endpoint 
---


# Automasi Deteksi Malware dan Blokir IP Terpusat dengan Platform Custom

Ide ini muncul ketika saya mengelola begitu banyak endpoint, tapi sayangnya akan cukup memakan waktu jika saya harus menginstall satu persatu Active Response, Yara Rules, dan mengintegrasikan dengan berbagai tools lain seperti wazuh,n8n, IRIS dsb

![Flowchart](/images/flowchart-1.png)


Gambar diatas adalah garis besar bagaimana integrasi berbagai platform kemanan dengan custom platform yang sedang saya kembangkan.

## Platform kemanan apa saja yang dipakai ?

1. Wazuh: Disini saya menggunakan wazuh sebagai SIEM, hal ini untuk memudahkan saya membuat berbagai rule yang dapat mendeteksi malicious activity yang tercatat di log.
2. n8n: Disini berfungsi sebagai SOAR (Security Orchestration, Automation, and Response) yang akan mengintegrasikan berbagai macam platform kemanan
3. Yara: tools ini akan di integrasikan dengan fitur FIM di wazuh, disini kita dapat membuat rules untuk mendeteksi berbagai malware varian baru

## Bagaimana Cara Kerja Custom Platform yang sedang dibuat ?

Cara kerjanya simple, dari berbagai log yang sudah dikumpulkan akan di klasifikasikan oleh wazuh apakah log tersebut malicious activity atau bukan, Selanjutnya jika log nya terdeteksi sebagai malicious activity akan dilempar ke n8n untuk selanjutnya diteruskan ke custom platform, nah kegunaan custom platform ini berguna untuk mengirimkan command untuk memblokir IP yang dicuragai sebagai attacker ke semua endpoint, hal ini akan memudahkan pekerjaan daripada harus mendistribusikan Active Response satu persatu ke endpoint endpoint tersebut

## Bagaimana dengan deteksi malware ?

Cara kerja nya sedikit mirip dengan blocking ip diatas, deteksi nya akan memanfaatkan fitur FIM (File Integrity Monitoring) di wazuh, jika terdapat suatu log nya menandakan penambahan/perubahan suatu file, log tersebut akan dilempar ke n8n yang akan diteruskan ke custom platform, selanjutnya custom platform tersebut akan memerintahkan endpoint untuk mengupload file tersebut ke API yang telah disiapkan, yang selanjutnya akan di scanning berdasarkan rules YARA, jika itu adalah suatu malware maka, custom platform ini akan memerintahkan endpoint untuk menghapus file tersebut

## Kenapa harus memakai n8n ? Kenapa tidak langsung integrasi dengan wazuh

Scenario diatas memang memungkinkan untuk di implementasikan, namun kita disini menggunakan SOAR seperti n8n untuk memudahkan mengelola integrasinya, yang kedepannya bisa saja di integrasikan dengan tools lain seperti IRIS