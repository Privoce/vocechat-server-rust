# Deploy with Docker

Docker supports x86 platforms. For ARM platforms, you may run our binary version directly. 

## 1. Quck start:  HTTP Way<span id=id1></span>

Fastest way to experience.
Schematic & Commands:
```
┌─────────┐                  ┌─────────┐  
│         │                  │         │  
│  Client ├─────────────────►│ vocechat│  
│         │                  │   3000  │  
└─────────┘                  └─────────┘  
```
Run on x86_64 platform:
```bash
docker run -d --restart=always \
  -p 3000:3000 \
  --name vocechat-server \
  privoce/vocechat-server:latest
```
Run on arm64 platform ( Apple M1, Aarch64 ):  
```bash
docker run -d --restart=always \
  -p 3000:3000 \
  --name vocechat-server \
  privoce/vocechat-server:latest-arm64
```

Visit: http://localhost:3000/

## 2. With HTTPS. Runs on 443 port. Auto SSL certificate. <span id=id2></span>
If you want https, vocechat-server also supports an auto application and installation of an SSL certificate. This mode requires the port 443 is not occupied, and a domain name points to the server IP.  
Schematic & Commands:
```
┌─────────┐                  ┌─────────┐
│         │                  │         │
│  Client ├─────────────────►│ vocechat│
│         │                  │   443   │
└─────────┘                  └─────────┘
```
```bash
mkdir -p ~/.vocechat-server/data
docker run -d --restart=always \
  -p 443:3000 \
  --name vocechat-server \
  -v ~/.vocechat-server/data:/home/vocechat-server/data \
  Privoce/vocechat-server:latest \
  --network.bind "0.0.0.0:443" \
  --network.domain "www.domain.com" \
  --network.tls.type "acme_tls_alpn_01" \
  --network.tls.acme.cache_path "/home/vocechat-server/data/cert"
```
Arguments description:  
network.bind: IP and port bound by the server, 0.0.0.0 means all.  
network.domain: if you plan to use TLS, you need specify a domain.  
network.type: TLS verification method, here is acme_tls_alpn_01,more refer to config/config.toml.  
network.tls.acme.cache_path: location of cetificate.    
network.tls.acme.directory_url: default verification authority, default "https://acme-v02.api.letsencrypt.org/directory".    
visit: https://www.domain.com/ .

If the 80/443 port is occupied by nginx, please refer to [Nginx Reverse proxy](install-by-docker-nginx.md)


## 3 Other Commands
### 3.1 Stop service
```bash
docker stop vocechat-server
```

### 3.2 View logs
```bash
docker logs -f vocechat-server
```

### 3.3 Backup data
```bash
cp -rf ~/.vocechat-server/data ~/.vocechat-server/backup
```

### 3.4 Update Docker image:
```shell
docker stop vocechat-server
docker rm vocechat-server
docker pull Privoce/vocechat-server:latest

# Modify to own parameter
docker run -d --restart=always \
  -p 3000:3000 \
  --name vocechat-server \
  Privoce/vocechat-server:latest  
```

### 3.5 Into Docker 
```shell
docker exec -it vocechat-server /bin/sh
cd /home/vocechat-server/data
```
If you need help, contact: han@privoce.com
