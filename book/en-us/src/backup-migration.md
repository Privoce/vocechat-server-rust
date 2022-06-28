# How to backup?
It's simple to backup vocechat-server, copy the data directory while making sure the service is stopped.

1. Stop service:  
```shell
docker stop vocechat-server
```

2. Backup data：  
```shell
cp -rf ~/.vocechat-server/data /backup/
```

3. Start service:
```shell
docker start vocechat-server
```

# How to migrate?
assume the old server is `old-server`, new server is `new-server`. they make the `ssh trust` each other, and installed rsync.

### 1. install a new version of vocechat-server
adjust parameters of docker:
```shell
mkdir -p ~/.vocechat-server/data
docker run -d --restart=always \
  -p 443:443 \
  --name vocechat-server \
  -v ~/.vocechat-server/data:/home/vocechat-server/data \
  Privoce/vocechat-server:latest \
  --network.bind "0.0.0.0:443" \
  --network.domain "www.domain.com" \
  --network.tls.type "acme_tls_alpn_01" \
  --network.tls.acme.cache_path "/home/vocechat-server/data/cert"
```
### 2. Stop vocechat-server on new-server
```shell
docker stop vocechat-server
```

### 3. copy data from old-server to new-server
```shell
cd ~/.vocechat-server/
rsync -av root@old-server:/root/.vocechat-server/* ./
```

### 4. start vocechat-server on new-server
```shell
docker start vocechat-server
```
