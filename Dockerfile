FROM alpine:3.16

COPY autoca /usr/local/bin/autoca
COPY config.yml.sample /usr/local/etc/config.yml

RUN chmod 755 /usr/local/bin/autoca


CMD ["/usr/local/bin/autoca", "-c", "/usr/local/etc/config.yml"]