# Printer-facing SMB share. Pinned by digest (alpine 3.24.2).
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

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
