# QBAnalyzer
QBAnalyzer is an open source threat intelligence framework that automates extracting artifacts and IOCs from file/dump into readable format.

![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/Peek%202019-11-04%2011-53.gif)

### E.g. Outputs
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

---

### Backstory
Back in 2018, I used to analyze many files and dumps using my old automated tools I developed in the past. The main tool called (QManager) that interacted with the rest of them through Pipes, APIs, Events sand RAW Files. The interaction happened in phases using a queue due to the variation and availability of some tools. Then, results were handled by a parser that piped structured and unstructured information into centralized databases. Finally, it informed me with the end of the process by sending a notification message. This worked just fine until recently when I wanted to implement some machine learning and few other features to the process. After a lot of researching I came to the conclusion that the best way is rewriting most of those old tools, and implement different opensource packages into modules. Then, have them compiled into one framework for easy management by researchers.

### Features
- Runs locally and easy to maintain
- Generates HTML and JSON as output
- Write your ideas under each output
- Different string/patterns analysis methods
- NL English words detection
- OCR words detections (!)
- IPS countries description
- IPS reserved hints
- World IPS countries image
- Ports description
- DNS servers description (Top servers)
- Websites similarity detection (Top 10000)
- Xrefs force directed image
- Xrefs count table
- MITRE att&ck tools detection (could be FP)
- MITRE att&ck patterns detection (could be FP)
- Similarity image
- Yara module and yara rules included
- JSON editable records 
- URL/EMAIL/TEL/Tags extraction
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
    - Manifest descriptions
    - Intent descriptions
    - Resources extraction
    - Symbs extraction
    - Classes extraction
    - Big functinon identification 
    - Xref detection
    - API Behavior detections
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
    - Attachment extraction

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
- Making the current yara rules into individual modules for further customization

### Recent update/phase 
- Cleaning up

### Depends on
Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img and a lot of researches.

### Libs
sre_parse, requests, r2pipe, scapy, queue, lzma, genericpath, nltk, cython_runtime, json, markupsafe, xml, pprint, signal, elftools, code, asyncio, codecs, qbanalyzer, token, encodings, glob, fcntl, OpenSSL, ssl, certifi, mimetypes, sqlite3, urllib, uu, hmac, bisect, multiprocessing, cryptography, binascii, xmlrpc, copyreg, collections, select, zipimport, fractions, concurrent, pytesseract, grp, tld, gzip, sre_compile, fnmatch, socket, subprocess, traceback, importlib, mmap, locale, marshal, calendar, cmd, warnings, datetime, inspect, numbers, urllib3, atexit, zope, platform, cffi, gettext, ctypes, sys, enum, hashlib, math, zlib, pyexpat, logging, struct, uuid, difflib, html, linecache, macholib, sitecustomize, six, stringprep, posix, weakref, opcode, re, runpy, site, ssdeep, zipfile, shutil, email, reprlib, netrc, types, functools, dis, quopri, pickle, pathlib, pkgutil, pefile, copy, decimal, ftplib, distutils, time, numpy, os, imp, unittest, yara, typing, pycparser, getopt, apport_python_hook, asyncore, posixpath, base64, asn1crypto, builtins, errno, bz2, sre_constants, array, optparse, pdb, operator, selectors, webbrowser, codeop, abc, PIL, chardet, gc, heapq, socketserver, magic, textwrap, tempfile, pydoc, resource, threading, http, keyword, itertools, ast, pwd, M2Crypto, ipaddress, csv, swig_runtime_data4, plistlib, ntpath, jinja2, shlex, ordlookup, tokenize, bdb, idna, simplejson, secrets, cgi, io, string, sysconfig, argparse, contextlib, regex, random, unicodedata, stat

### Disclaimer
- This project:
    - Is a result of compiling many researches/studies, use it in researching only (If i missed a reference/dependency, please let me know!) 
    - Is NOT an anti malware project and does not quarantine or delete malicious files (If you are interested in anti malware project, contact me and i will explain what dependencies/libs need be re-written)
    - Generates large html objects (You may need to wait few seconds on them to be load)
    
---
   
### Run it
```sh
git clone git@github.com:bd249ce4/QBAnalyzer.git
cd QBAnalyzer
chmod +x install.sh
./install.sh
python3 -m qbanalyzer.cli
```

### Run it with docker
```docker
git clone git@github.com:bd249ce4/QBAnalyzer.git
sudo docker build . -t qbanalyzer && sudo docker run -it -v /home/localfolder:/localfolder qbanalyzer
```
---

### Screenshots
Write your thoughts and findings
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/textarea.png)

PE information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pe.png)

WIN API and C functions Description
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/winapi1.png)

Sections Description
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/winsecs.png)

Resources Description
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/cdes.png)

Dll Description
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/dlls.png)

PE Signature
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/sigextract.png)

PE Extraction
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/siginfo.png)

PE Manifest
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/manfiest.png)

DMG plist information 
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/dmginfo.png)

MACHO resources
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/res.png)

MACHO Sections
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/mac1.png)

MACHO Libs
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/mac2.png)

MACHO Symbols
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/machosym.png)

DMG shell extraction 
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/shellextract.png)

ELF sections
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/linuxsecs.png)

ELF Symbols
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/elfsym.png)

BB HEADER information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/bb1.png)

BB DATA information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/bb2.png)

BB Functions and strings
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/bbfs.png)

APK information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/dexinfo.png)

APK permissions information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/apkper.png)

APK classes
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/apkclasses.png)

APK externals
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/apkex.png)

APK symbols
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/apksymbols.png)

APK big functions
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/apkfuncs.png)

PCAP HTTP
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap10.png)

PCAP DNS
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap2.png)

PCAP PORTs
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap5.png)

PCAP Frames
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap4.png)

PCAP IPs
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap6.png)

PCAP WAP detection
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/detectfirewall.png)

YARA
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/yara.png)

NL English detection
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/eng.png)

OCR detection
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/ocrdetection.png)

Unknown word
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/unkn.png)

URLs detection
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/urldet.png)

DNS Servers detection
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/dnsservers.png)

URLs similarity
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/urlsim.png)

MITRE description
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/mitre.png)

MITRE information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/mitreinfo.png)

Extracted files
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/extract.png)

Email information
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/emailinfo.png)

Email attachment extraction
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/attachments.png)

Office info 
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/officeinfo.png)

Office bin extraction 
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/officebinextract.png)

RTF object
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/rtfnobjects.png)

RTF object dump
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/rtfobjectdump.png)

Email patterns
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/emailextract.png)

Behavior APIs
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/behavior.png)

Xref count
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/xrefscount.png)

PDF keys
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pdfkeys.png)

PDF objects
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pdfobjects.png)

PDF stream parsing
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/flatstreamparsed.png)

Xref force directed image
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/xrefstree.png)

PCAP IPs MAP
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/pcap7.png)

Similarity image
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/sim.png)

