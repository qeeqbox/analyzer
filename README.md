~~~~
  _____   _____   _____  __   _  _____        \   /   _____  ______  _____
 |     | |_____] |_____| | \  | |_____| |      \_/    ____/ |______ |_____/
 |____\| |_____] |     | |  \_| |     | |_____  |    /_____ |______ |    \ ∞
                                                |                          
~~~~

# QBAnalyzer
QBAnalyzer is a threat intelligence framework for extracting artifacts and IOCs from file/dump into readable format.

### Architecture
![](https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/withoutint.png)

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
- MS office module
- Machine learning modules
- Refactoring modules v2

### Recent update/phase 
- Simplified accessing data dict

### Depends on
Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img and a lot of researches.

### Libs
resource, posix, numpy, itertools, macholib, calendar, difflib, math, encodings, certifi, ntpath, apport_python_hook, tld, weakref, bz2, ctypes, runpy, argparse, queue, sre_constants, platform, cgi, zope, simplejson, ssl, ordlookup, copy, tempfile, heapq, html, lzma, urllib, stringprep, atexit, stat, unicodedata, functools, concurrent, genericpath, r2pipe, datetime, pdb, sys, asyncio, builtins, logging, qbanalyzer, gc, mmap, ssdeep, elftools, codecs, zipimport, gzip, cryptography, os, fnmatch, threading, ast, sqlite3, sitecustomize, numbers, subprocess, selectors, collections, glob, linecache, scapy, io, idna, reprlib, dis, ipaddress, cython_runtime, enum, fractions, errno, pprint, hashlib, select, textwrap, random, email, webbrowser, uu, pydoc, zipfile, marshal, mimetypes, jinja2, multiprocessing, importlib, sre_parse, binascii, signal, yara, PIL, bisect, inspect, bdb, warnings, requests, opcode, fcntl, tokenize, pytesseract, sysconfig, types, traceback, contextlib, json, site, socket, sre_compile, shlex, six, unittest, urllib3, nltk, http, struct, xml, plistlib, re, cffi, array, chardet, magic, pyexpat, abc, secrets, token, base64, shutil, zlib, pycparser, distutils, posixpath, asn1crypto, decimal, keyword, uuid, optparse, hmac, markupsafe, gettext, string, cmd, quopri, pwd, operator, pkgutil, code, pefile, copyreg, csv, OpenSSL, codeop, time, grp, pathlib, getopt, pickle, locale 

### Disclaimer
- This project:
    - Is a result of compiling many researches/studies, use it in researching only (If i missed a reference/dependency, please let me know!) 
    - Is NOT an anti malware project and does not quarantine or delete malicious files (If you are interested in anti malware project, contact me and i will explain what dependencies/libs need be re-written)
    - Generates large html objects (You may need to wait few seconds on them to be load)

### Examples
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
Step 1/9 : FROM python:3
 ---> 60e318e4984a
Step 2/9 : RUN apt-get update && apt-get install -y curl libfuzzy-dev yara libmagic-dev libjansson-dev
 ---> Using cache
 ---> 73806233a032
Step 3/9 : RUN pip install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy
 ---> Using cache
 ---> cfd27cee5c57
Step 4/9 : RUN python -m nltk.downloader words
 ---> Using cache
 ---> 21ab04cabdce
Step 5/9 : RUN ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
 ---> Using cache
 ---> dba0ee3f6b6c
Step 6/9 : RUN pip install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
 ---> Using cache
 ---> 58bd90288959
Step 7/9 : WORKDIR /app
 ---> Using cache
 ---> 14d674a78fab
Step 8/9 : COPY qbanalyzer qbanalyzer
 ---> Using cache
 ---> 3d6251393ee5
Step 9/9 : CMD ["python", "-m","qbanalyzer.cli"]
 ---> Using cache
 ---> c4457a7562c3
Successfully built c4457a7562c3
Successfully tagged qbanalyzer:latest
2019-10-12 02:15:56,661 ✓ Starting StaticAnalyzer
2019-10-12 02:15:56,762 ✓ Starting MitreParser
2019-10-12 02:15:56,763 ✓ Parsing Mitre databases
2019-10-12 02:15:57,172 ✓ Starting QBMitresearch
2019-10-12 02:15:57,275 ✓ Starting QBStrings
2019-10-12 02:15:57,594 ✓ Starting WindowsPe
2019-10-12 02:15:57,695 ✓ Starting LinuxELF
2019-10-12 02:15:57,897 ✓ Starting Macho
2019-10-12 02:15:57,998 ✓ Starting ApkParser
2019-10-12 02:15:58,100 ✓ Starting BBParser (Experimental)
2019-10-12 02:15:58,202 ✓ Starting YaraParser
2019-10-12 02:16:00,066 ✓ Starting WafDetect
2019-10-12 02:16:00,168 ✓ Starting ReadPackets
2019-10-12 02:16:00,269 ✓ Starting QBImage
2019-10-12 02:16:00,370 ✓ Starting HtmlMaker
2019-10-12 02:16:00,474 ✓ Starting EmailsParser
2019-10-12 02:16:00,674 ✓ Starting QBIntell
2019-10-12 02:16:00,876 ✓ Starting QBXrefs
2019-10-12 02:16:00,978 ✓ Starting QBOCRDetect
2019-10-12 02:16:01,079 ✓ Starting URLSimilarity
(Cmd) analyze --file /localmalwarefolder/mal --output /localfolder/ --open yes
2019-10-06 21:33:38,915 ! getdebug failed..
2019-10-06 21:33:38,935 ✓ Added descriptions to strings
2019-10-06 21:33:39,637 ✓ Added descriptions to strings
2019-10-06 21:33:40,539 ✓ Added descriptions to strings
2019-10-06 21:33:40,640 ✓ Added descriptions to strings
2019-10-06 21:33:40,741 ✓ Added descriptions to strings
2019-10-06 21:33:40,981 ✓ Detecting english strings
2019-10-06 21:33:41,086 ✓ Added descriptions to strings
2019-10-06 21:33:41,086 ✓ Added descriptions to strings
2019-10-06 21:33:41,220 ✓ Making symbol xrefs
2019-10-06 21:33:47,420 ✓ Analyze windows APIs
2019-10-06 21:33:47,638 ✓ Making file tables
2019-10-06 21:33:47,844 ✓ Making a visualized image
2019-10-06 21:33:48,721 → Generated Html file /localfolder/0fe8d113b826c9b46947bd9af598380a/html
```

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

