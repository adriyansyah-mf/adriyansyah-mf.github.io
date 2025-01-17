---
layout: post
title: Amankan server dari judol dan webshell dengan yara dan wazuh
category: cybersecurity
tags: [cybersecurity,wazuh,blue team,wazuh,yara]
fullview: false
description : Amankan server dari judol dan webshell dengan yara dan wazuh
---


# tldr;

```
Apa itu Wazuh ?
Wazuh adalah sebuah platform keamanan yang berfokus pada deteksi ancaman dan keamanan endpoint. Ini mencakup kemampuan monitoring, deteksi, dan respons terhadap ancaman keamanan pada lingkungan IT. Wazuh menyediakan fitur seperti deteksi serangan, analisis log, integritas file, dan monitoring keamanan berbasis aturan.

Apa itu yara ?

sebuah tool yang mengklasifikasikan apakah suatu binary,code, dll itu adalah malware atau bukan berdasarkan rules yang kita buat.

sumber: ChatGPT 
```
```
Contoh rule yara kaya apa sir ?

rule detect_gambling {
    meta: 
        author = "Adriyansyah MF @ Solusi247"
        date = "2025-01-17"
    strings:
        $string0 = "gacor"
        $string1 = "maxwin"
        $string2 = "wetogel"
        $string3 = "togel"
        $string4 = "toto"
        $string5 = "bet"
        $string6 = "jackpot"
        $string7 = "poker"
        $string8 = "casino"
        $string9 = "judi"
        $string10 = "bola"
        $string11 = "slot"
        $string12 = "sabung"

    condition:
        2 of them
}
```
diatas adalah contoh rule untuk deteksi judol dsb
kalo ngomongin yara bakal lebih komplek, next artikel deh wkwkwkw 


# Intermeso

Akhir akhir ini serangan dari hemker penyepong bandar judol makin hari makin ganas. Karena itu sudah sewajarnya kita mengamankan server yang kita kelola. Sebenernya langkah untuk mengamankan ini ada banyak cara, salah satunya dengan menggunakan wazuh FIM dan yara


![Flowchart](/images/wazuh.jpg)


Sebelum ke tahap selanjutnya, Install dlu wazuh server, wazuh agent, dan yara

## Setup wazuh untuk deteksi perubahan dengan modul FIM ?

1. Setelah semua ter-install, setup FIM untuk memonitor path yang sekiranya rawan menjadi tempat Threat Actor untuk meletakan filenya. disini saya mengarahkan pada folder /var/www/html/, bisa di sesuaikan dengan kebetuhan
   
   ```xml
    <syscheck>
      <directories realtime="yes" check_all="yes" report_changes="yes" whodata="yes">/var/www/html/</directories>
    </syscheck>
   ```

2. Setelah setup FIM nya, kita config dulu wazuh servernya seperti berikut
   
   ```xml
        <command>
            <name>yara_linux</name>
            <executable>yara.py</executable>
            <timeout_allowed>no</timeout_allowed>
        </command>
    

        <active-response>
            <command>yara_linux</command>
            <location>local</location>
            <rules_id>554,550</rules_id>
        </active-response>
    ```
3. Copykan 2 script ini di server yang telah terinstall wazuh agent:
   ```sh
        #!/bin/bash
    # Wazuh - Yara active response
    # Copyright (C) 2015-2022, Wazuh Inc.
    #
    # This program is free software; you can redistribute it
    # and/or modify it under the terms of the GNU General Public
    # License (version 2) as published by the FSF - Free Software
    # Foundation.


    #------------------------- Gather parameters -------------------------#

    # Extra arguments
    read INPUT_JSON
    YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
    YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
    FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

    # Set LOG_FILE path
    LOG_FILE="logs/active-responses.log"

    size=0
    actual_size=$(stat -c %s ${FILENAME})
    while [ ${size} -ne ${actual_size} ]; do
        sleep 1
        size=${actual_size}
        actual_size=$(stat -c %s ${FILENAME})
    done

    #----------------------- Analyze parameters -----------------------#

    if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
    then
        echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
        exit 1
    fi

    #------------------------- Main workflow --------------------------#

    # Execute Yara scan on the specified filename
    yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

    if [[ $yara_output != "" ]]
    then
        # Iterate every detected rule and append it to the LOG_FILE
        while read -r line; do
            echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
        done <<< "$yara_output"
    fi

    exit 0;


   ```
   simpan file diatas dengan nama yara.sh

   ```python
    #!/usr/bin/python3
    import sys
    import json
    import os
    import datetime
    import subprocess
    from pathlib import PureWindowsPath, PurePosixPath


    if os.name == "nt":
        LOG_FILE = (
            "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
        )
    else:
        LOG_FILE = "/var/ossec/logs/active-responses.log"


    def write_debug_file(ar_name, msg):
        with open(LOG_FILE, mode="a") as log_file:
            ar_name_posix = str(
                PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response") :]))
            )
            log_file.write(
                str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
                + " "
                + ar_name_posix
                + ": "
                + msg
                + "\n"
            )

    def write_log_yara(msg):
        with open(LOG_FILE, mode="a") as log_file:
            log_file.write(msg)


    def main(argv):

        write_debug_file(argv[0], "Starting Yara Engine")
        input_str = ""
        for line in sys.stdin:
            input_str += line
            break
        write_debug_file(argv[0], input_str)
        try:
            data = json.loads(input_str)
        except json.JSONDecodeError as e:
            write_debug_file(argv[0], "disana")
            print(f"Error parsing JSON: {e}")
            sys.exit(1)
        filename = data["parameters"]["alert"]["syscheck"]["path"]
        write_debug_file(argv[0], filename)
        write_debug_file(argv[0], "sini gaaa")
        try:
            command = f"yara -C -w -r -f -m /home/<USERNAME>/compiled-rules.yar {filename}"
            yara_output = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            write_debug_file(argv[0], f"YARA scan completed: {yara_output.stdout}")
        except subprocess.CalledProcessError as e:
            write_debug_file(argv[0], str(e))
        except Exception as e:
            write_debug_file(argv[0], str(e))

        if yara_output.stdout.strip():
            for line in yara_output.stdout.splitlines():
                write_log_yara(f"wazuh-yara: INFO - Scan result: {line}")
            quarantine_path = "/tmp/quarantined"
            os.makedirs(quarantine_path, exist_ok=True)
            command = f"mv {filename} {quarantine_path}"
            subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            write_debug_file(argv[0], f"{filename} moved to {quarantine_path}")

        print("Execution Success\n")


    if __name__ == "__main__":
        main(sys.argv)


   ```
   dan file diatas dengan nama yara.py

   kedua file diatas disimpan di /var/ossec/active-response/bin/

   Cara kerjanya adalah, jika ada suatu file yang ditambahkan atau di rubah sesuai dengan rule wazuh, maka akan di move ke folder /tmp/

4. Setelah ke dua script diatas terpasang, clone rules dari repo ini ke /home/{USERNAME}/

```bash
git clone https://github.com/adriyansyah-mf/yara-rules.git
```

rules diatas bukan hanya deteksi gacor dsb, tapi juga deteksi beberapa webshell seperti gecko shell,bypasserv shell dsb
oiya, ini rule yang udah di compile 

Inspirasi artikel ini dari:
https://mastomi.id/articles/2025-01/cegah-website-tampilkan-konten-judol-dengan-cloudflare-worker
