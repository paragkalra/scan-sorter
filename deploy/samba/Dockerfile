# Printer-facing SMB share. Pinned by digest (alpine 3.24.2).
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

# UID/GID must match the worker so it can rename scans out of the inbox.
ARG SCANNER_UID=10001
ARG SCANSORTER_GID=10001

RUN apk add --no-cache samba-server=4.23.8-r0 samba-common-tools=4.23.8-r0 tini \
    && addgroup -g "${SCANSORTER_GID}" scansorter \
    && adduser -D -H -s /sbin/nologin -u "${SCANNER_UID}" -G scansorter scanner \
    && mkdir -p /inbox /var/log/samba \
    && chown scanner:scansorter /inbox && chmod 0770 /inbox

COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh && testparm -s /etc/samba/smb.conf >/dev/null

EXPOSE 445
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
