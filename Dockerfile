FROM python:3
RUN apt-get update && apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swigswig
RUN pip3 install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tldRUN python -m nltk.downloader words
RUN ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
RUN pip install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
WORKDIR /app
COPY qbanalyzer qbanalyzer
CMD ["python", "-m","qbanalyzer.cli"]
