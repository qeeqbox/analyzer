FROM python:3
RUN apt-get update && apt-get install -y curl libfuzzy-dev yara libmagic-dev libjansson-dev radare2 tesseract-ocr libtesseract-dev swig libssl-dev
RUN pip install numpy pyelftools macholib macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytessearct M2Crypto
RUN python -m nltk.downloader words
RUN ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
RUN pip install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
WORKDIR /app
COPY qbanalyzer qbanalyzer
CMD ["python", "-m","qbanalyzer.cli"]
