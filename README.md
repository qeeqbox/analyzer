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

### Roadmap
- ~~Reduce file I/O~~
- ~~PDF module~~
- ~~RTF module~~
- ~~Fix htmlmaker (return concat(self.root_render_func(self.new_context(vars))) MemoryError) due to rendering large objects.. this happened due to yara module appending too many results that caused htmlmaker to hang . Solved by grouping yara results into one~~
- MS office module
- Machine learning modules
- Refactoring modules v2

### Update
Thank you for reaching out!! I have been getting requests to implement the following:
- Curling info from virustotal, hybridanalysis, Any.Run and Jotti through their apis
- ~~Making the current yara rules into individual modules for further customization~~ (rolled back but added extra plugins)

### Recent update/phase 
- Cleaning up

### Depends on
Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img, font-awesome, flag-icon-css and a lot of researches.

### Libs
socketserver, zope, codecs, simplejson, concurrent, pefile, xml, shlex, mmap, locale, pathlib, csv, hmac, token, queue, scapy, html, types, inspect, functools, nltk, site, genericpath, secrets, re, os, sre_parse, qbanalyzer, threading, shutil, mimetypes, struct, optparse, pickle, cffi, cryptography, bdb, urllib, plistlib, zipimport, tempfile, sre_compile, runpy, opcode, elftools, magic, uu, sqlite3, ctypes, chardet, ntpath, enum, argparse, array, codeop, datetime, selectors, heapq, distutils, logging, posix, pytesseract, requests, jinja2, contextlib, cmd, collections, email, calendar, decimal, M2Crypto, unittest, swig_runtime_data4, tokenize, json, sitecustomize, grp, sysconfig, random, six, subprocess, pwd, ftplib, reprlib, ordlookup, ssdeep, cgi, PIL, ssl, sre_constants, gzip, apport_python_hook, tld, typing, warnings, platform, getopt, pyexpat, zlib, abc, idna, stringprep, select, cython_runtime, certifi, multiprocessing, keyword, r2pipe, sys, pdb, regex, resource, code, pydoc, copyreg, difflib, urllib3, uuid, ast, itertools, string, signal, fnmatch, xmlrpc, quopri, ipaddress, numbers, numpy, weakref, importlib, bz2, math, asyncio, binascii, traceback, encodings, pycparser, lzma, http, errno, glob, asn1crypto, gc, fcntl, bisect, unicodedata, textwrap, builtins, macholib, imp, marshal, pprint, yara, markupsafe, hashlib, linecache, posixpath, socket, base64, time, OpenSSL, asyncore, atexit, fractions, dis, copy, zipfile, pkgutil, gettext, webbrowser, netrc

### Disclaimer
- This project:
    - Is a result of compiling many researches/studies, use it in researching only (If i missed a reference/dependency, please let me know!) 
    - Is NOT an anti malware project and does not quarantine or delete malicious files (If you are interested in anti malware project, contact me and i will explain what dependencies/libs need be re-written)
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
