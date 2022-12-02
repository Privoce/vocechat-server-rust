FROM alpine as certs
RUN apk update && apk add ca-certificates

FROM busybox
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

COPY vocechat-server /home/vocechat-server/vocechat-server
COPY config /home/vocechat-server/config
# COPY wwwroot /home/vocechat-server/wwwroot
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

#RUN vocechat -r -u 1000 -g vocechat
#USER vocechat

EXPOSE 3000

WORKDIR /home/vocechat-server
ENTRYPOINT ["/docker-entrypoint.sh"]
# CMD ["/home/vocechat-server/vocechat-server", "/home/vocechat-server/config/config.toml"]
# ENTRYPOINT ["/home/vocechat-server/vocechat-server", "/home/vocechat-server/config/config.toml"]
