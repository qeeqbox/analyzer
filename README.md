# QBAnalyzer
QBAnalyzer is an open source threat intelligence framework that automates extracting artifacts and IoCs from file/dump into readable format

### Running
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/introv01.10.gif)

### E.g. HTML Outputs
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

### E.g. Output json
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

---

### Features
- Runs locally (Offline)
- Analyze buffer, file or full folder
- Interactive analysis (Session is saved)
- Generates HTML or JSON as output
- General file information MD5, charset, mime, ssdeep
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
- Whitelist implemented (Windows7,8 and 10 files)
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
- Archives
    - Extract mimes and guess by extensions
    - Finding patterns in all unpacked files
    - Encrypted archives detection
- HTML
    - Extract scripts, iframes, links and forms
    - Decode/analyze links
    - Script entropy

more..

### Roadmap 2019
- ~~Reduce file I/O~~
- ~~PDF module~~
- ~~RTF module~~
- ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- ~~HTML module~~
- ~~Refactoring modules v2~~
- ~~Whitelist~~
- Web detection

### Roadmap 2020
- Phishing module
- MS office module
- Web service and API
- Machine learning modules (maybe commercial)

### Update
Thank you for reaching out - I have been getting requests to implement the following:
- Curling info from virustotal, hybridanalysis, Any.Run and Jotti through their apis
- ~~Making the current yara rules into individual modules for further customization~~ (rolled back but added extra plugins)

### All dependencies
Docker, Python3, Bootstrap, Javascript, jquery, D3.js, JSON, Html, Mongodb, Wikipedia, Linux\MacOS\Windows\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img, font-awesome, flag-icon-css, bdb, r2pipe, operator, codeop, pwd, sys, pyexpat, math, cmd, importlib, io, markupsafe, quopri, platform, pkgutil, random, tldextract, typing, swig_runtime_data4, copyreg, glob, difflib, code, zipimport, stat, time, secrets, optparse, urllib, xml, M2Crypto, fractions, pydoc, PIL, abc, elftools, calendar, atexit, ctypes, datetime, fcntl, sre_constants, runpy, uu, sqlite3, sitecustomize, distutils, cgi, lzma, site, email, certifi, requests_file, jinja2, pycparser, selectors, unicodedata, pytesseract, gettext, encodings, nltk, select, apport_python_hook, linecache, itertools, tld, textwrap, cryptography, xmlrpc, zipfile, mmap, pefile, ftplib, socketserver, asyncio, asn1crypto, cython_runtime, uuid, bz2, webbrowser, chardet, functools, ipaddress, enum, hashlib, tempfile, queue, pathlib, base64, ordlookup, copy, getopt, scapy, ast, codecs, posix, marshal, urllib3, sre_parse, netrc, heapq, bs4, cffi, builtins, pickle, errno, grp, os, fnmatch, genericpath, qbanalyzer, shutil, magic, string, re, signal, decimal, pkg_resources, inspect, pdb, stringprep, binascii, argparse, sre_compile, http, opcode, plistlib, six, collections, gc, posixpath, ssl, asyncore, numpy, bisect, simplejson, ntpath, numbers, macholib, token, keyword, imp, traceback, zlib, logging, soupsieve, yara, requests, contextvars, ssdeep, pprint, sysconfig, tokenize, gzip, struct, csv, array, idna, shlex, warnings, dis, unittest, html, threading, weakref, locale, socket, json, resource, contextlib, hmac, reprlib, concurrent, types, subprocess, mimetypes, psutil and tons of researches..


If i missed a reference/dependency, please let me know!

### Disclaimer
This project is NOT an anti malware project and does not quarantine or delete malicious files
    
---

### [![Generic badge](https://img.shields.io/badge/ubuntu19-passed-success.svg)](https://github.com/bd249ce4/QBAnalyzer/) Run it in Ubuntu 
```sh
git clone https://github.com/qeeqbox/QBAnalyzer.git
cd QBAnalyzer
chmod +x install.sh
./install.sh ubuntu
./install.sh initdb
python3 -m app.cli
```

### [![Generic badge](https://img.shields.io/badge/Fedora31-passed-success.svg)](https://github.com/bd249ce4/QBAnalyzer/) Run it in Fedora 
```sh
git clone https://github.com/qeeqbox/QBAnalyzer.git
cd QBAnalyzer
chmod +x install.sh
./install.sh fedora
./install.sh initdb
python3 -m app.cli
```

### [![Generic badge](https://img.shields.io/badge/kali-passed-success.svg)](https://github.com/bd249ce4/QBAnalyzer/) Run it in Kali
```sh
git clone https://github.com/qeeqbox/QBAnalyzer.git
cd QBAnalyzer
chmod +x install.sh
./install.sh kali
./install.sh initdb
python3 -m app.cli
```

### [![Generic badge](https://img.shields.io/badge/docker19-passed-success.svg)](https://github.com/bd249ce4/QBAnalyzer/) Run it in Docker
```docker
git clone https://github.com/qeeqbox/QBAnalyzer.git
sudo docker build . -t qbanalyzer && sudo docker run -it -v /home/localfolder:/localfolder qbanalyzer
```

---
<p align="center"> <img src="https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/madewithlove.png"></p>
