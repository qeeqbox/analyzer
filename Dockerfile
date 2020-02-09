FROM ubuntu:latest
ENV analyzer_env=local
RUN apt-get update && apt-get install -y curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb python3 python3-pip libevent-dev supervisor
RUN pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo pyOpenSSL oletools extract_msg requests flask werkzeug gunicorn flask_mongoengine flask_admin flask_login flask_bcrypt pyOpenSSL Flask-Markdown psutil gevent python-dateutil
RUN python3 -m nltk.downloader words punkt wordnet
RUN ln -s /usr/local/lib/python3.7/site-packages/usr/local/lib/libyara.so /usr/local/lib/libyara.so
RUN pip3 install --global-option="build" --global-option="--enable-cuckoo" --global-option="--enable-magic" yara-python
ADD ./ /analyzer
COPY ./databases databases
COPY ./initdb.sh initdb.sh
RUN chmod 777 initdb.sh
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
CMD supervisord -c /etc/supervisor/conf.d/supervisord.conf -n