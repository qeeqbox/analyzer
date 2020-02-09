FROM mongo:3.4.8
RUN echo "America/Los_Angeles" > /etc/timezone
RUN dpkg-reconfigure -f noninteractive tzdata
COPY ./databases databases
COPY ./initdb.sh /docker-entrypoint-initdb.d/initdb.sh
RUN chmod 777 /docker-entrypoint-initdb.d/initdb.sh