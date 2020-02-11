<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/analyzerlogo.png"></p>

#
[![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=version&query=$.version&colorB=blue)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=docker&query=$.docker&colorB=green)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=docker-compose&query=$.dockercompose&colorB=green)](https://github.com/qeeqbox/analyzer/blob/master/changes.md)

Threat intelligence framework for extracting artifacts and IoCs from file/dump into readable format

## Flat Web Interface
<img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/webintro18.gif" style="max-width:768px"/>

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
- Snort support
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
    - Snort parsing
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
- OLE (wrapper)
    - Number of objects
    - Object extraction
    - Macros extraction
- EMAIL (built-in and wrapper)
    - Header information
    - Attachment extraction and parsing 
    - Extract body
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
    - AlienVault
    - PulseDive

## Roadmap
- &#9745; ~~Reduce file I/O~~
- &#9745; ~~PDF module~~
- &#9745; ~~RTF module~~
- &#9745; ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- &#9745; ~~HTML module~~
- &#9745; ~~Refactoring modules v2~~
- &#9745; ~~Converting some yara rules into individual modules (Requested by users)~~
- &#9745; ~~Whitelist (Requested by users)~~
- &#9745; ~~Switching to mongodb (Requested by users)~~
- &#9745; ~~Phishing module~~
- &#9745; ~~Web service and API~~
- &#9745; ~~Web interface (Requested by users)~~
- &#9745; ~~Curling some TIPs (Requested by users)~~
- &#9745; ~~MS office module~~
- &#9745; ~~Snort wrapper (Requested by users)~~
- Offline multiscanner (Requested by users)
- Java analysis (Requested by users)
- Web detection
- Machine learning modules (maybe commercial)

## Prerequisites
apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb

pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo flask pyOpenSSL oletools extract_msg

Prerequisites packages are required for some modules (If you are having issues using those packages, I might be able to share with you my own alternatives that I developed in the past in C#\C)

## Running
#### Run it as Web interface with Dockerfile 
git clone https://github.com/qeeqbox/analyzer.git <br>
cd analyzer <br>
sudo docker build -t analyzer . && sudo docker run -d -p 8000:8000 analyzer <br>
http://127.0.0.1:8000/login/ <br>

#### Run it as Web interface with docker-compose
git clone https://github.com/qeeqbox/analyzer.git <br>
cd analyzer <br>
docker-compose up --build <br>
http://127.0.0.1:8000/login/ <br>

## Media
- [inquest](https://inquest.net/newsletter/issue015)
- [ncybersec](https://zh-cn.facebook.com/ncybersec/posts/1391635004340553)
- [secwiki](https://wiki.ourren.com/news?tag=tools)

## Resources
Linux\MacOS\Windows\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, PEID, cisco umbrella and tons of researches.. (If i missed a resource/dependency, please let me know!)

## Other Licenses
#### By using this framework, you are accepting the license terms of each package listed below:
python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo flask pyOpenSSL oletools extract_msg

## Disclaimer\Notes
- This project is NOT an anti malware project and does not quarantine or delete malicious files
- If you are interested in adopting some features in your project, please mention this source somewhere in your project
