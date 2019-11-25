# QBAnalyzer
QBAnalyzer is an open source threat intelligence framework that automates extracting artifacts and IOCs from file/dump into readable format.

### Running
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/intro.gif)

### E.g. HTML Outputs
- [Linux-Xorddos](https://bd249ce4.github.io/pages/Xorddos.html)
- [Android-BrazilianRAT](https://bd249ce4.github.io/pages/BrRAT.apk.html)
- [Android-Ransom](https://bd249ce4.github.io/pages/sexSimulator.apk.html)
- [macOS-DMG-BundloreAdware](https://bd249ce4.github.io/pages/BundloreAdware.dmg.html)
- [Windows-GoziBankerISFB](https://bd249ce4.github.io/pages/GoziBankerISFB.exe.html)
- [PDF-TrojanDownloader](https://bd249ce4.github.io/pages/Downloader.pdf.html)
- [PCAP-dump](https://bd249ce4.github.io/pages/dump.pcap.html)
- [Office-JSDropper](https://bd249ce4.github.io/pages/officejsdropper.docx.html)
- [RTF-Downloader](https://bd249ce4.github.io/pages/f9boo3.doc.html)
- [EMAIL-Shademalspam](https://bd249ce4.github.io/pages/Shaderansomwaremalspam.eml.html)

### E.g. Output json
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/json.gif)

---

### Backstory
Back in 2018, I used to analyze many files and dumps using my old automated tools I developed in the past. The main tool called (QManager) that interacted with the rest of them through Pipes, APIs, Events sand RAW Files. The interaction happened in phases using a queue due to the variation and availability of some tools. Then, results were handled by a parser that piped structured and unstructured information into centralized databases. Finally, it informed me with the end of the process by sending a notification message. This worked just fine until recently when I wanted to implement some machine learning and few other features to the process. After a lot of researching I came to the conclusion that the best way is rewriting most of those old tools, and implement different opensource packages into modules. Then, have them compiled into one framework for easy management by researchers.

### Features
- Runs locally and easy to maintain
- Generates HTML and JSON as output
- Write your ideas under each output
- General file information MD5, charset, mime, ssdeep
- Different string/patterns analysis methods
- NL English words detection
- OCR words detections (!)
- IPS countries description
- IPS reserved hints
- World IPS countries image
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
    - Frame Filter
    - HTTP Filter
    - DNS Filter
    - ARP Filter
    - WAF Detection
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

### Roadmap 2020 
- Machine learning modules (Separate modules)

### Roadmap 2019
- ~~Reduce file I/O~~
- ~~PDF module~~
- ~~RTF module~~
- ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- ~~Refactoring modules v2~~
- MS office module

### Update
Thank you for reaching out!! I have been getting requests to implement the following:
- Curling info from virustotal, hybridanalysis, Any.Run and Jotti through their apis
- ~~Making the current yara rules into individual modules for further customization~~ (rolled back but added extra plugins)

### Recent update/phase 
- Cleaning up

### Depends on
Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, PEiD, 7z, Cisco Umbrella, font-awesome, flag-icon.

### Libs
sre_parse, netrc, itertools, sre_compile, codeop, gzip, pwd, six, pprint, socketserver, ast, magic, elftools, subprocess, typing, zope, difflib, plistlib, hmac, zipfile, weakref, types, copy, textwrap, r2pipe, token, opcode, cryptography, site, zlib, idna, locale, ipaddress, ntpath, distutils, shlex, cffi, traceback, ssdeep, ctypes, builtins, ssl, simplejson, sre_constants, string, glob, pyexpat, scapy, lzma, markupsafe, operator, cython_runtime, warnings, swig_runtime_data4, abc, pathlib, cgi, getopt, multiprocessing, inspect, code, errno, html, tempfile, secrets, argparse, datetime, ftplib, sys, pycparser, struct, pefile, resource, numpy, PIL, asyncio, sysconfig, xmlrpc, posixpath, selectors, yara, bisect, quopri, urllib3, macholib, threading, heapq, M2Crypto, cmd, platform, uu, stringprep, stat, importlib, io, http, codecs, sqlite3, logging, mimetypes, queue, random, certifi, zipimport, uuid, asyncore, reprlib, ordlookup, encodings, fnmatch, functools, copyreg, collections, decimal, hashlib, os, optparse, requests, binascii, qbanalyzer, webbrowser, pkgutil, mmap, imp, select, time, socket, calendar, contextlib, nltk, pickle, OpenSSL, atexit, jinja2, unicodedata, json, runpy, gc, bz2, pytesseract, fractions, dis, unittest, chardet, linecache, enum, urllib, tld, bdb, array, concurrent, xml, signal, genericpath, email, base64, numbers, regex, grp, fcntl, csv, posix, math, marshal, sitecustomize, apport_python_hook, asn1crypto, keyword, pdb, pydoc, tokenize, re, shutil, gettext

### Disclaimer
- This project:
    - Is a result of compiling many researches/studies, use it in researching only (If i missed a reference/dependency, please let me know!) 
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
