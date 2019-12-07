# QBAnalyzer
QBAnalyzer is an open source threat intelligence framework that automates extracting artifacts and IOCs from file/dump into readable format.

### Running
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/introv1.09.gif)

### E.g. HTML Outputs
- [Linux-Xorddos](https://bd249ce4.github.io/pages/2019/Xorddos.html)
- [Android-BrazilianRAT](https://bd249ce4.github.io/pages/2019/BrRAT.apk.html)
- [Android-Ransom](https://bd249ce4.github.io/pages/2019/sexSimulator.apk.html)
- [macOS-DMG-BundloreAdware](https://bd249ce4.github.io/pages/2019/BundloreAdware.dmg.html)
- [Windows-GoziBankerISFB](https://bd249ce4.github.io/pages/2019/GoziBankerISFB.exe.html)
- [PDF-TrojanDownloader](https://bd249ce4.github.io/pages/2019/Downloader.pdf.html)
- [PCAP-dump](https://bd249ce4.github.io/pages/2019/PCAPdump.html)
- [Office-JSDropper](https://bd249ce4.github.io/pages/2019/OfficeJSDropper.docx.html)
- [RTF-Downloader](https://bd249ce4.github.io/pages/2019/f9boo3.doc.html)
- [EMAIL-Shademalspam](https://bd249ce4.github.io/pages/2019/Shaderansomwaremalspam.eml.html)

### E.g. Output json
- [Linux-Xorddos](https://bd249ce4.github.io/pages/2019/Xorddos.json)
- [Android-BrazilianRAT](https://bd249ce4.github.io/pages/2019/BrRAT.apk.json)
- [Android-Ransom](https://bd249ce4.github.io/pages/2019/sexSimulator.apk.json)
- [macOS-DMG-BundloreAdware](https://bd249ce4.github.io/pages/2019/BundloreAdware.dmg.json)
- [Windows-GoziBankerISFB](https://bd249ce4.github.io/pages/2019/GoziBankerISFB.exe.json)
- [PDF-TrojanDownloader](https://bd249ce4.github.io/pages/2019/Downloader.pdf.json)
- [PCAP-dump](https://bd249ce4.github.io/pages/2019/PCAPdump.json)
- [Office-JSDropper](https://bd249ce4.github.io/pages/2019/OfficeJSDropper.docx.json)
- [RTF-Downloader](https://bd249ce4.github.io/pages/2019/f9boo3.doc.json)
- [EMAIL-Shademalspam](https://bd249ce4.github.io/pages/2019/Shaderansomwaremalspam.eml.json)

---

### Features
- Runs locally and easy to maintain
- Analyze full folder or individual file
- Generates HTML or JSON as output
- Write your ideas under each output
- General file information MD5, charset, mime, ssdeep
- Different string/patterns analysis methods
- NL English words detection
- OCR words detections (!)
- IPS countries description
- IPS reserved hints
- World IPS countries image
- World IPS countries flags
- Ports description
- DNS servers description (Top servers)
- Websites similarity detection (Top 10000)
- Artifacts force directed image
- Xrefs force directed image
- Xrefs count table
- MITRE att&ck tools detection (could be FP)
- MITRE att&ck patterns detection (could be FP)
- Similarity image
- Yara module and yara rules included
- JSON editable records 
- URL/EMAIL/TEL/Tags common patterns extraction
- Credit cards patterns extraction
- Encryption patterns (base64, md5, sha1..) detection
- DGA (domain generation algorithm) patterns detection 
- BOM detection
- Interacting analysis
- Credential extractor
- Linux
    - ELF information
    - API functions descriptions
    - System commands descriptions
    - Secitons descriptions
    - Lib descriptions
    - Encrypted section detection
    - Symbs extraction
    - MITRE artifacts detection
    - Xref detection
    - Behavior detections
- macOS
    - DMG extraction
    - Shell code detection
    - PLIST information
    - MITRE artifacts detection
    - macOS information
- Windows
    - PE information
    - Encrypted section detection
    - Secitons descriptions
    - DLL descriptions
    - Symbs extraction
    - Signature extraction
    - API functions descriptions
    - PE ASLR, DEP, SEH and CFG detection
    - MITRE artifacts detection
    - API Behavior detections (DLL injection, Process Hollowing, Process Doppelganging etc..)
    - Xref detection
- Android
    - APK information
    - DEX information
    - Manifest descriptions
    - Intent descriptions
    - Resources extraction
    - Symbs extraction
    - Classes extraction
    - Big functinon identification 
    - Xref detection
    - API Behavior detections
- Iphone
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
    - DGA detction
- PDF
    - Objects enumeration
    - Keys (javascript, js, OpenAction) enumeration
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
- HTML
    - Extract scripts, iframes, links and forms
    - Decode/analyze links
    - Script entropy

### Roadmap
- ~~Reduce file I/O~~
- ~~PDF module~~
- ~~RTF module~~
- ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- ~~HTML module~~
- ~~Refactoring modules v2~~
- Web API
- Whitelist
- MS office module
- Machine learning modules (2019)

### Update
Thank you for reaching out!! I have been getting requests to implement the following:
- Curling info from virustotal, hybridanalysis, Any.Run and Jotti through their apis
- ~~Making the current yara rules into individual modules for further customization~~ (rolled back but added extra plugins)

### Recent update/phase 
- Cleaning up

### Depends on
Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux/MacOS/Windows/Android Documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img, font-awesome, flag-icon-css and a tons of researches.

### Libs
bdb, r2pipe, operator, codeop, pwd, sys, pyexpat, math, cmd, importlib, io, markupsafe, quopri, platform, pkgutil, random, tldextract, typing, swig_runtime_data4, copyreg, glob, difflib, code, zipimport, stat, time, secrets, optparse, urllib, xml, M2Crypto, fractions, pydoc, PIL, abc, elftools, calendar, atexit, ctypes, datetime, fcntl, sre_constants, runpy, uu, sqlite3, sitecustomize, distutils, cgi, lzma, site, email, certifi, requests_file, jinja2, pycparser, selectors, unicodedata, pytesseract, gettext, encodings, nltk, select, apport_python_hook, linecache, itertools, tld, textwrap, cryptography, xmlrpc, zipfile, mmap, pefile, ftplib, socketserver, asyncio, asn1crypto, cython_runtime, uuid, bz2, webbrowser, chardet, functools, ipaddress, enum, hashlib, tempfile, queue, pathlib, base64, ordlookup, copy, getopt, scapy, ast, codecs, posix, marshal, urllib3, sre_parse, netrc, heapq, bs4, cffi, builtins, pickle, errno, grp, os, fnmatch, genericpath, qbanalyzer, shutil, magic, string, re, signal, decimal, pkg_resources, inspect, pdb, stringprep, binascii, argparse, sre_compile, http, opcode, plistlib, six, collections, gc, posixpath, ssl, asyncore, numpy, bisect, simplejson, ntpath, numbers, macholib, token, keyword, imp, traceback, zlib, logging, soupsieve, yara, requests, contextvars, ssdeep, pprint, sysconfig, tokenize, gzip, struct, csv, array, idna, shlex, warnings, dis, unittest, html, threading, weakref, locale, socket, json, resource, contextlib, hmac, reprlib, concurrent, types, subprocess, mimetypes

### Disclaimer
- This project:
    - Is a result of compiling many researches/studies (If i missed a reference/dependency, please let me know!) 
    - Is NOT an anti malware project and does not quarantine or delete malicious files (If you are interested in anti malware project, contact me and i will explain what dependencies/libs need to be re-written)
    - Generates large html objects (You may need to wait few seconds on them to be load)
    
---
   
### Run it
```sh
git clone https://github.com/bd249ce4/QBAnalyzer.git
cd QBAnalyzer
chmod +x install.sh
./install.sh
python3 -m qbanalyzer.cli
```

### Run it with docker
```docker
git clone https://github.com/bd249ce4/QBAnalyzer.git
sudo docker build . -t qbanalyzer && sudo docker run -it -v /home/localfolder:/localfolder qbanalyzer
```
