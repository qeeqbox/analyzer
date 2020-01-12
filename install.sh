if [[ $1 == "fedora" ]];then
	dnf groupinstall -y "Development Tools"
	dnf install -y libffi-devel python3 python3-devel python3-pip ssdeep-devel ssdeep-libs swig openssl-devel p7zip radare2 yara jansson-devel file-devel
	pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil flask pyOpenSSL
	python3 -m nltk.downloader words wordnet punkt
	ln -s /usr/bin/7za /usr/bin/7z
	ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
	pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
elif [[ $1 == "ubuntu" || $1 == "kali" ]]; then
	apt-get update && apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb
	pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo pyOpenSSL 
	python3 -m nltk.downloader words wordnet punkt
	ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
	pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
fi