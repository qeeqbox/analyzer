#  QeeqBox Analyzer
[![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=version&query=$.version&colorB=blue)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/ubuntu19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/Fedora31-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/docker19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/kali-passed-success.svg)](https://github.com/qeeqbox/analyzer/)

Threat intelligence framework for extracting artifacts and IoCs from file/dump into readable format

![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/introv01.10.gif)

## Output
#### HTML Outputs
- [putty-clean](https://bd249ce4.github.io/pages/2019/putty.exe.html)
- [Linux-Xorddos](https://bd249ce4.github.io/pages/2019/Xorddos.html)
- [Android-BrazilianRAT](https://bd249ce4.github.io/pages/2019/BrRAT.apk.html)
- [Android-Ransom](https://bd249ce4.github.io/pages/2019/sexSimulator.apk.html)
- [macOS-DMG-BundloreAdware](https://bd249ce4.github.io/pages/2019/BundloreAdware.dmg.html)
- [Windows-GoziBankerISFB](https://bd249ce4.github.io/pages/2019/GoziBankerISFB.exe.html)
- [PDF-TrojanDownloader](https://bd249ce4.github.io/pages/2019/Downloader.pdf.html)
- [PCAP-dump](https://bd249ce4.github.io/pages/2019/PCAPdump.html)
- [Office-JSDropper](https://bd249ce4.github.io/pages/2019/OfficeJSDropper.html)
- [RTF-Downloader](https://bd249ce4.github.io/pages/2019/f9boo3.doc.html)
- [EMAIL-Shademalspam](https://bd249ce4.github.io/pages/2019/Shaderansomwaremalspam.eml.html)
- [putty-clean](https://bd249ce4.github.io/pages/2019/putty.exe.html)

#### Output json
- [putty-clean](https://bd249ce4.github.io/pages/2019/putty.exe.json)
- [Linux-Xorddos](https://bd249ce4.github.io/pages/2019/Xorddos.json)
- [Android-BrazilianRAT](https://bd249ce4.github.io/pages/2019/BrRAT.apk.json)
- [Android-Ransom](https://bd249ce4.github.io/pages/2019/sexSimulator.apk.json)
- [macOS-DMG-BundloreAdware](https://bd249ce4.github.io/pages/2019/BundloreAdware.dmg.json)
- [Windows-GoziBankerISFB](https://bd249ce4.github.io/pages/2019/GoziBankerISFB.exe.json)
- [PDF-TrojanDownloader](https://bd249ce4.github.io/pages/2019/Downloader.pdf.json)
- [PCAP-dump](https://bd249ce4.github.io/pages/2019/PCAPdump.json)
- [Office-JSDropper](https://bd249ce4.github.io/pages/2019/OfficeJSDropper.json)
- [RTF-Downloader](https://bd249ce4.github.io/pages/2019/f9boo3.doc.json)
- [EMAIL-Shademalspam](https://bd249ce4.github.io/pages/2019/Shaderansomwaremalspam.eml.json)

## General Features
- Runs locally (Offline)
- Analyze buffer, file or full folder
- Intime analysis (Session is saved)
- 2 modes (Interactive and silent)
- Generates HTML or JSON as output
- Dump output file with details to mongodb
- Save raw json result to mongodb
- Basic file information MD5, charset, mime, ssdeep
- Different string/patterns analysis methods
- NL English words detection
- OCR words detection
- IPS hints and countries description
- Ports hints
- World IPS world image and flags
- DNS servers description (Top servers)
- Websites similarity detection (Top 10000)
- Artifacts force directed image
- Cross references force directed image and table
- MITRE att&ck tools and patterns detection (could be FP)
- Similarity image divided to classes
- YARA module and YARA rules included
- YARA module includes conditions
- URL/EMAIL/TEL/Tags patterns extraction
- Credit Cards patterns extraction
- Credential patterns extraction
- Encryption patterns (base64, md5, sha1..) extraction
- DGA (Domain Generation Algorithm) patterns extraction 
- BOM (Byte Order Mark) detection
- URL shorteners extraction
- ASCII extraction from UNICODE
- Whitelist implemented (Windows7, 8 and 10 files)
- Check WAF and bypass proxy
- Free/Fake email extraction
- Spelling and punctuation check
- Top phishing words included

## Other Features
- Linux
    - ELF information
    - API functions descriptions
    - System commands descriptions
    - Sections descriptions
    - Lib descriptions
    - Encrypted section detection
    - Symbols extraction
    - MITRE artifacts mapped to detection
    - Cross references detection
    - Behavior detection
- macOS
    - DMG extraction
    - Shell code detection
    - PLIST information
    - MITRE artifacts mapped to detection
    - macOS information
- Windows
    - PE information
    - Encrypted section detection
    - Sections descriptions
    - DLL descriptions
    - Symbols extraction
    - Signature extraction and validation
    - API descriptions
    - PE ASLR, DEP, SEH and CFG detection
    - MITRE artifacts mapped to detection
    - API Behavior detection (DLL injection, Process Hollowing, Process Doppelganging etc..)
    - Cross references detection
    - Icon extraction
    - Extract String file info (FileDescription, FileDescription etc..)
- Android
    - APK information
    - DEX information
    - Manifest descriptions
    - Intent descriptions
    - Resources extraction
    - Symbols extraction
    - Classes extraction
    - Big functions identification 
    - Cross references detection
    - API Behavior detection
- IPhone
    - IPA information
- BlackBerry (COD)
    - COD information
    - Functions extraction
    - Strings extraction
- PCAP
    - Frame filter
    - HTTP filter
    - DNS filter
    - ARP filter
    - WAF detection
    - DGA detection
- PDF
    - Objects enumeration
    - Keys (javascript, js, OpenAction) extraction
    - Streams parsing
    - String analysis
- Office[x]
    - Meta info extraction
    - Hyper and target links extraction
    - Bin printable parser
- RTF
    - Number of objects
    - Object extraction
- EMAIL
    - Header information
    - Attachment extraction and parsing 
    - Phishing patterns check
- Archives
    - Extract mimes and guess by extensions
    - Finding patterns in all unpacked files
    - Encrypted archives detection
- HTML
    - Extract scripts, iframes, links and forms
    - Decode/analyze links
    - Script entropy

## Web api and interface
- Testing or researching only
- Track tasks by uuid
- https (auto generate self signed certificate)
- Dump json or html from mongodb database

## Roadmap
- ~~Reduce file I/O~~
- ~~PDF module~~
- ~~RTF module~~
- ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- ~~HTML module~~
- ~~Refactoring modules v2~~
- ~~Converting some yara rules into individual modules (Requested by users)~~
- ~~Whitelist (Requested by users)~~
- ~~Switching to mongodb (Requested by users)~~
- ~~Phishing module~~
- ~~Web service and API~~
- Web detection
- Curling some TIPs (Requested by users)
- MS office module
- Machine learning modules (maybe commercial)

## Prerequisites
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb
</code></pre>

<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo flask pyOpenSSL
</code></pre>

## Running as application

#### Run it in Ubuntu 
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh ubuntu
./install.sh initdb
python3 -m framework.cli --interactive
</code></pre>

#### Run it in Fedora 
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh fedora
./install.sh initdb
python3 -m framework.cli --interactive
</code></pre>

#### Run it in Kali
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh kali
./install.sh initdb
python3 -m framework.cli --interactive
</code></pre>


#### Run it in Docker
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
sudo docker build . -t analyzer && sudo docker run -it -v /home/localfolder:/localfolder analyzer
</code></pre>


## Intro options
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
                                                            
 _____  __   _  _____        \   / ______  ______  _____   
|_____| | \  | |_____| |      \_/   ____/ |______ |_____/
|     | |  \_| |     | |_____  |   /_____ |______ |    \ 2020.V.02.04
                               |  https://github.com/QeeqBox/Analyzer
                                                            
Please choose a mode:
--interactive         Run this framework as an application
--silent              Run this framework as service (Required an interface for interaction)

Examples:
python3 -m framework.cli --interactive
python3 -m framework.cli --silent
</code></pre>

## Interactive mode
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
(interactive) help analyze
usage: analyze [-h] [--file FILE] [--folder FOLDER] [--buffer BUFFER]
               [--type TYPE] [--behavior] [--xref] [--yara] [--language]
               [--mitre] [--topurl] [--ocr] [--enc] [--cards] [--creds]
               [--patterns] [--suspicious] [--dga] [--plugins] [--visualize]
               [--flags] [--icons] [--worldmap] [--spelling] [--image]
               [--full] [--phishing] [--uuid UUID] [--unicode] [--bigfile]
               [--w_internal] [--w_original] [--w_hash] [--w_words] [--w_all]
               [--output OUTPUT] [--disk_dump_html] [--disk_dump_json]
               [--open] [--print_json] [--db_result] [--db_dump_html]
               [--db_dump_json]

Input arguments:
  --file FILE       path to file or dump
  --folder FOLDER   path to folder
  --buffer BUFFER   input buffer
  --type TYPE       force input type

Analysis switches:
  --behavior        check with generic detections
  --xref            get cross references
  --yara            analyze with yara module (Disable this for big files)
  --language        analyze words against english language
  --mitre           map strings to mitre
  --topurl          get urls and check them against top 10000
  --ocr             get all ocr text
  --enc             find encryptions
  --cards           find credit cards
  --creds           find credit cards
  --patterns        find common patterns
  --suspicious      find suspicious strings
  --dga             find Domain generation algorithms
  --plugins         scan with external plugins
  --visualize       visualize some artifacts
  --flags           add countries flags to html
  --icons           add executable icons to html
  --worldmap        add world map to html
  --spelling        force spelling check
  --image           add similarity image to html
  --full            analyze using all modules
  --phishing        analyze phishing content
  --uuid UUID       task id
  --print_json      print output to terminal

Force analysis switches:
  --unicode         force extracting ascii
  --bigfile         force analyze big files

Whitelist switches:
  --w_internal      find it in white list by internal name
  --w_original      find it in white list by original name
  --w_hash          find it in white list by hash
  --w_words         check extracted words against whitelist
  --w_all           find it in white list

Output arguments and switches:
  --output OUTPUT   path of output folder
  --disk_dump_html  save html record to disk
  --disk_dump_json  save json record to disk
  --open            open the report in webbroswer

Database options:
  --db_result       save results to db (<16mg)
  --db_dump_html    save html dump tp db
  --db_dump_json    save json dump tp db

Examples:
    analyze --folder /home/malware --full --disk_dump_html --disk_dump_json --db_dump_html --db_dump_json --open
    analyze --file /malware/BrRAT.apk --full --db_dump_json --print_json
    analyze --folder /malware --full --db_dump_json --open
    analyze --folder /malware --output /outputfolder --yara --mitre --ocr --disk_dump_json --open
    analyze --buffer "google.com bit.ly" --topurl --db_dump_html --open
    analyze --buffer "google.com bit.ly" --full --print_json
</code></pre>

## Silent mode
Create task
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
curl https://localhost:8001/qeeqbox/analyzer/tasks/create -d '{"buffer": "goo9le.com","full":"True","print":"True","json":"True", "open":"True"}' -H 'Content-Type: application/json' --insecure
</code></pre>
The response will be
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
{"task":"809cad06-917f-43e1-b02c-8aab68e17110"}
</code></pre>
Get the task output
<pre><code style="background-color:#EEEEEE;font-family:Consolas,Monaco">
curl https://localserver:8001/qeeqbox/analyzer/tasks/get/json/809cad06-917f-43e1-b02c-8aab68e17110 --insecure
</code></pre>

## Other use
It took very long time making many features of this project adoptable to other project, if you are interested in adopting some features in your project, please mention this source somewhere in your project.

## Resources
Linux\MacOS\Windows\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, PEID and tons of researches.. (If i missed a resource/dependency, please let me know!)

## Disclaimer
This project is NOT an anti malware project and does not quarantine or delete malicious files

<p align="center"> <img src="https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/madewithlove.png"></p>
