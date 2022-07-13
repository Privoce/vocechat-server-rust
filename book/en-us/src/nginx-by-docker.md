# Deploy nginx by docker

## Quick deploy HTTP site:
```shell
mkdir -p /home/nginx/conf/conf.d
mkdir -p /home/nginx/log
mkdir -p /home/wwwroot/rocket.voce.chat
echo "hello, world!" > /home/wwwroot/rocket.voce.chat/index.html
cat > /home/nginx/conf/conf.d/rocket.voce.chat.conf << EOF
server {
    listen 80;
    server_name rocket.voce.chat;
    location / {
        root   /home/wwwroot/rocket.voce.chat;
        index  index.html index.htm;
    }
}
EOF
docker stop nginx;
docker rm nginx;
docker run -itd \
    --restart=always \
    --name nginx \
    -p 80:80 \
    -v /home/nginx/conf/conf.d/rocket.voce.chat.conf:/etc/nginx/conf.d/rocket.voce.chat.conf \
    -v /home/nginx/log:/var/log/nginx \
    -v /home/wwwroot/:/home/wwwroot/ \
    nginx
tail -f /home/nginx/log/*.log    
```
access: https://rocket.voce.chat/

## Deploy HTTPS site
Prepare the certificate file, rocket.voce.chat.crt, rocket.voce.chat.keys
```shell
mkdir -p /home/nginx/conf/cert
cp -rf rocket.voce.chat.crt /home/nginx/conf/cert/
cp -rf rocket.voce.chat.key /home/nginx/conf/cert/

mkdir -p /home/nginx/conf/conf.d
mkdir -p /home/nginx/log
mkdir -p /home/wwwroot/rocket.voce.chat
echo "hello, world!" > /home/wwwroot/rocket.voce.chat/index.html
cat > /home/nginx/conf/conf.d/rocket.voce.chat.conf << EOF
server {
    listen 80;
    server_name rocket.voce.chat;
    return 301 https://rocket.voce.chat$request_uri;
}
server {
    listen       443 default_server;
    server_name  rocket.voce.chat; # Change to your own domain name
    ssl on;
    ssl_certificate cert/rocket.voce.chat.crt; # Change to your own CRT file storage path
    ssl_certificate_key cert/rocket.voce.chat.key;    # Change to your own key file storage path
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    location / {
        root   /home/wwwroot/rocket.voce.chat;
        index  index.html index.htm;
    }
}
EOF
docker stop nginx;
docker rm nginx;
docker run -itd \
    --restart=always \
    --name nginx \
    -p 80:80 \
    -p 443:443 \
    -v /home/nginx/conf/conf.d/rocket.voce.chat.conf:/etc/nginx/conf.d/rocket.voce.chat.conf \
    -v /home/nginx/conf/cert:/etc/nginx/cert \
    -v /home/nginx/log:/var/log/nginx \
    -v /home/wwwroot/:/home/wwwroot/ \
    nginx
tail -f /home/nginx/log/*.log    
```
access: https://rocket.voce.chat/