sudo apt-get update && apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2
sudo pip3 install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld
python3 -m nltk.downloader words
ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
sudo pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
