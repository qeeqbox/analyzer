if [[ $1 == "fedora" ]];then
	sudo dnf groupinstall -y "Development Tools"
	sudo dnf install -y libffi-devel python3 python3-devel python3-pip ssdeep-devel ssdeep-libs swig openssl-devel p7zip radare2 yara jansson-devel file-devel
	sudo pip3 install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil
	sudo python3 -m nltk.downloader words
	sudo ln -s /usr/bin/7za /usr/bin/7z
	sudo ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
	sudo pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
elif [[ $1 == "ubuntu" ]]; then
	sudo apt-get update && apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img
	sudo pip3 install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil
	sudo python3 -m nltk.downloader words
	sudo ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
	sudo pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
fi
