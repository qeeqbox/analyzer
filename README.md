<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/analyzerlogo.png"></p>

#
[![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=version&query=$.version&colorB=blue)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/ubuntu19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/Fedora31-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/docker19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) [![Generic badge](https://img.shields.io/badge/kali-passed-success.svg)](https://github.com/qeeqbox/analyzer/)

Threat intelligence framework for extracting artifacts and IoCs from file/dump into readable format

## Flat Web Interface
<img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/webinterfacenew.gif" style="width:100%;"/>

## CLI Interface
<img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/intro.gif" style="width:100%;"/>

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
- Web interface
- Supports threat intelligence platform feeds

## Other Features
- Linux (wrapper)
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
- macOS (wrapper)
    - DMG extraction
    - Shell code detection
    - PLIST information
    - MITRE artifacts mapped to detection
    - macOS information
- Windows (wrapper)
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
- Android (wrapper)
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
- IPhone (built-in)
    - IPA information
- BlackBerry (COD) (built-in)
    - COD information
    - Functions extraction
    - Strings extraction
- PCAP (wrapper)
    - Frame filter
    - HTTP filter
    - DNS filter
    - ARP filter
    - WAF detection
    - DGA detection
- PDF (built-in)
    - Objects enumeration
    - Keys (javascript, js, OpenAction) extraction
    - Streams parsing
    - String analysis
- Office (built-in and wrapper)
    - Meta info extraction
    - Hyper and target links extraction
    - Bin printable parser
    - Extract Text
    - Extract DDE
    - Macros extraction
- MS (built-in and wrapper)
    - Number of objects
    - Object extraction
    - Macros extraction
- EMAIL (built-in)
    - Header information
    - Attachment extraction and parsing 
    - Phishing patterns check
- Archives (wrapper)
    - Extract mimes and guess by extensions
    - Finding patterns in all unpacked files
    - Encrypted archives detection
- HTML (wrapper)
    - Extract scripts, iframes, links and forms
    - Decode/analyze links
    - Script entropy
- Online TIPs (Required tokens)
    - HybridAnalysis
    - MalShare
    - MetaDefender
    - VirusTotal

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
- ~~Web interface (Requested by users)~~
- ~~Curling some TIPs (Requested by users)~~
- ~~MS office module~~
- java analysis (Requested by users)
- offline multiscanner (Requested by users)
- Web detection
- Machine learning modules (maybe commercial)

## Prerequisites
<pre style="font-family:Consolas,Monaco">
apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb
</pre>

<pre style="font-family:Consolas,Monaco">
pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo flask pyOpenSSL oletools
</pre>

## Running
#### Run it as Web interface 
<pre style="font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
docker-compose up --build
https://127.0.0.1:8000/login/
</pre>

#### Run it as CLI
<pre style="font-family:Consolas,Monaco">
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x initdb.sh
chmod +x install.sh
./install.sh ubuntu
service mongodb start
./initdb.sh
cd ..
python3 -m analyzer.cli --interactive --local
</pre>

## Other use
If you are interested in adopting some features in your project, please mention this source somewhere in your project.

## Resources
Linux\MacOS\Windows\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, PEID, cisco umbrella and tons of researches.. (If i missed a resource/dependency, please let me know!)

## Disclaimer
- This project is NOT an anti malware project and does not quarantine or delete malicious files
- Prerequisites packages are required for some modules (If you are having issues using those packages, I might be able to share with you my own alternatives that I developed in the past in C#\C)
