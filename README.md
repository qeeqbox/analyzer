# QeeqBox Analyzer
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

## Features
- Runs locally (Offline)
- Analyze buffer, file or full folder
- Intime analysis (Session is saved)
- 2 modes (Interactive and silent)
- Generates HTML or JSON as output
- Dump output file with details to mongodb
- Save output result to mongodb
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
- Whitelist implemented (Windows7, 8 and 10 files)
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
- Archives
    - Extract mimes and guess by extensions
    - Finding patterns in all unpacked files
    - Encrypted archives detection
- HTML
    - Extract scripts, iframes, links and forms
    - Decode/analyze links
    - Script entropy

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
- Web detection
- Phishing module
- Curling some TIPs (Requested by users)
- MS office module
- Web service and API
- Machine learning modules (maybe commercial)

## All dependencies
Docker, Python3, Bootstrap, Javascript, jquery, D3.js, JSON, Html, Mongodb, Wikipedia, Linux\MacOS\Windows\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img, font-awesome, flag-icon-css, bdb, r2pipe, operator, codeop, pwd, sys, pyexpat, math, cmd, importlib, io, markupsafe, quopri, platform, pkgutil, random, tldextract, typing, swig_runtime_data4, copyreg, glob, difflib, code, zipimport, stat, time, secrets, optparse, urllib, xml, M2Crypto, fractions, pydoc, PIL, abc, elftools, calendar, atexit, ctypes, datetime, fcntl, sre_constants, runpy, uu, sqlite3, sitecustomize, distutils, cgi, lzma, site, email, certifi, requests_file, jinja2, pycparser, selectors, unicodedata, pytesseract, gettext, encodings, nltk, select, apport_python_hook, linecache, itertools, tld, textwrap, cryptography, xmlrpc, zipfile, mmap, pefile, ftplib, socketserver, asyncio, asn1crypto, cython_runtime, uuid, bz2, webbrowser, chardet, functools, ipaddress, enum, hashlib, tempfile, queue, pathlib, base64, ordlookup, copy, getopt, scapy, ast, codecs, posix, marshal, urllib3, sre_parse, netrc, heapq, bs4, cffi, builtins, pickle, errno, grp, os, fnmatch, genericpath, qbanalyzer, shutil, magic, string, re, signal, decimal, pkg_resources, inspect, pdb, stringprep, binascii, argparse, sre_compile, http, opcode, plistlib, six, collections, gc, posixpath, ssl, asyncore, numpy, bisect, simplejson, ntpath, numbers, macholib, token, keyword, imp, traceback, zlib, logging, soupsieve, yara, requests, contextvars, ssdeep, pprint, sysconfig, tokenize, gzip, struct, csv, array, idna, shlex, warnings, dis, unittest, html, threading, weakref, locale, socket, json, resource, contextlib, hmac, reprlib, concurrent, types, subprocess, mimetypes, psutil and tons of researches.. (If i missed a reference/dependency, please let me know!)

## Running as application

#### [![Generic badge](https://img.shields.io/badge/ubuntu19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) Run it in Ubuntu 
```sh
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh ubuntu
./install.sh initdb
python3 -m app.cli --interactive
```

#### [![Generic badge](https://img.shields.io/badge/Fedora31-passed-success.svg)](https://github.com/qeeqbox/analyzer/) Run it in Fedora 
```sh
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh fedora
./install.sh initdb
python3 -m app.cli --interactive
```

#### [![Generic badge](https://img.shields.io/badge/kali-passed-success.svg)](https://github.com/qeeqbox/analyzer/) Run it in Kali
```sh
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x install.sh
./install.sh kali
./install.sh initdb
python3 -m app.cli --interactive
```

#### [![Generic badge](https://img.shields.io/badge/docker19-passed-success.svg)](https://github.com/qeeqbox/analyzer/) Run it in Docker
```docker
git clone https://github.com/qeeqbox/analyzer.git
sudo docker build . -t analyzer && sudo docker run -it -v /home/localfolder:/localfolder analyzer
```

## Intro options
```
 _____  __   _  _____        \   / ______  ______  _____   
|_____| | \  | |_____| |      \_/   ____/ |______ |_____/
|     | |  \_| |     | |_____  |   /_____ |______ |    \ 2020.V.02.01b
                               |  https://github.com/QeeqBox/Analyzer
                                                            
Please choose a mode:
--interactive         Run this framework as an application
--silent              Run this framework as service (Required an interface for interaction)

Examples:
python3 -m app.cli --interactive
python3 -m app.cli --silent
```

## Interactive mode
```
(interactive) help analyze
usage: analyze [-h] [--file FILE] [--folder FOLDER] [--buffer BUFFER]
               [--behavior] [--xref] [--yara] [--language] [--mitre]
               [--topurl] [--ocr] [--enc] [--cards] [--creds] [--patterns]
               [--suspicious] [--dga] [--plugins] [--visualize] [--flags]
               [--icons] [--print] [--worldmap] [--image] [--full] [--unicode]
               [--bigfile] [--w_internal] [--w_original] [--w_hash]
               [--w_words] [--w_all] [--output OUTPUT] [--html] [--json]
               [--open] [--db]

Input arguments:
  --file FILE      path to file or dump
  --folder FOLDER  path to folder
  --buffer BUFFER  input buffer

Analysis switches:
  --behavior       check with generic detections
  --xref           get cross references
  --yara           analyze with yara module (Disable this for big files)
  --language       analyze words against english language
  --mitre          map strings to mitre
  --topurl         get urls and check them against top 10000
  --ocr            get all ocr text
  --enc            find encryptions
  --cards          find credit cards
  --creds          find credit cards
  --patterns       find common patterns
  --suspicious     find suspicious strings
  --dga            find Domain generation algorithms
  --plugins        scan with external plugins
  --visualize      visualize some artifacts
  --flags          add countries flags to html
  --icons          add executable icons to html
  --print          print output to terminal
  --worldmap       add world map to html
  --image          add similarity image to html
  --full           analyze using all modules

Force analysis switches:
  --unicode        force extracting ascii
  --bigfile        force analyze big files

Whitelist switches:
  --w_internal     find it in white list by internal name
  --w_original     find it in white list by original name
  --w_hash         find it in white list by hash
  --w_words        check extracted words against whitelist
  --w_all          find it in white list

Output arguments and switches:
  --output OUTPUT  path of output folder
  --html           make html record
  --json           make json record
  --open           open the report in webbroswer

Database options:
  --db_result      save results to db (<16mg)
  --db_dump        save json dump tp db

Examples:
    analyze --file /malware/GoziBankerISFB.exe --full --html --json --print --open
    analyze --file /malware/BrRAT.apk --full --json --print
    analyze --folder /malware --full --json --open
    analyze --folder /malware --output /outputfolder --yara --mitre --ocr --json --open
    analyze --buffer "google.com bit.ly" --topurl --html --open
    analyze --buffer "google.com bit.ly" --full --json --print

```

## Silent mode
You can add tasks to this queue by using insert from qbjobqueue (I'll add additional details later on)

## Disclaimer
This project is NOT an anti malware project and does not quarantine or delete malicious files

<p align="center"> <img src="https://raw.githubusercontent.com/bd249ce4/QBAnalyzer/master/readme/madewithlove.png"></p>
