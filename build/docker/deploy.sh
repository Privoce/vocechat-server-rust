#!/bin/bash

mkdir -p ~/.vocechat-server/data/cert
docker stop vocechat-server
docker rm vocechat-server
docker pull Privoce/vocechat-server:latest
docker run -d --restart=always \
  -p 443:443 \
  --name vocechat-server \
  -v ~/.vocechat-server/data:/home/vocechat-server/data \
  Privoce/vocechat-server:latest \
  --network.bind "0.0.0.0:443" \
  --network.domain "chat.domain.com" \
  --network.tls.type "acme_tls_alpn_01" \
  --network.tls.acme.directory_url "https://acme-v02.api.letsencrypt.org/directory" \
  --network.tls.acme.cache_path "/home/vocechat-server/data/cert"
docker logs -f vocechat-server