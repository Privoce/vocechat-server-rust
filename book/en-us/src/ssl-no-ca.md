# No certificate requested 
The previous chapters [Docker](install-by-docker.md) and [Shell](install-by-shell.md)
have included how to install the vocechat-server and apply for certificates automatically. 
Therefore, for most cases, you do not need to read this chapter and do it manually.

Vocechat-server supports custom certificates and supports to apply for certificate automatically.

## 1. Preparation

### 1.1 Prepare a domain name
Change `A Record` of domain to server IP.

### 1.2. Confirm that port 443 is not occupied
Checking whether port is occupied with following command:
```shell
netstat -nlpt|grep 443
```

## 2. Modify configuration
Modify config/config Toml, vocechat-server, the default bind is 3000, which is changed to 443 here  
### 2.1 Custom certificate
If you have applied for a certificate, copy and paste the contents of the certificate.
```shell
[network]
bind = "0.0.0.0:443"
domain = "www.domain.com"

[network.tls]
type = "certificate"
cert = """multi lines"""
key = """multi lines"""
```
### 2.2. Automatically apply for and renew certificate
The server automatically applly for certificate and renew certificate. This method is recommended.
```shell
[network]
bind = "0.0.0.0:443"
domain = "www.domain.com"

[network.tls]
type = "acme_tls_alpn_01"
cache_path = "data/cert"
```

### 2.3 Self-Signed certificate
Self signed certificate, the browser side will prompt the risk, and the client can use it normally.
```shell
[network]
bind = "0.0.0.0:443"
domain = "www.domain.com"

[network.tls]
type = "self_signed"
```

# 3. Restart vocechat-server
```shell
docker restart vocechat-server
# or
/etc/init.d/vocechat-server.sh restart
```

# 4. Verify
Access https://www.domain.com/


