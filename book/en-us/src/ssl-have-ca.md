# Already have your own Certificate
The previous chapters [Docker](install-by-docker.md) and [Shell](install-by-shell.md) have included 
how to make `vocechat-server` automatically apply for certificates.
Therefore, under normal environment, you do not need to read this chapter. 
If you already have your own certificate, you can implement it through the following configuration.

### 1. You need to have a domain name, assuming domain.com, and has pointed to the server's WAN IP.
### 2. Configure config/config.toml
```shell
[network]
bind = "0.0.0.0:443" # must be 443
domain = "domain.com" # Change to your own domain name

[network.tls]
type = "certificate"
cert = """....""" # Copy the certificate contents here directly
key = """...."""  # The private key is copied here directly
```
### 3. Start vocechat-server
```shell
vocechat-server config/config.toml
```

After the service is started, there will be a prompt for certificate application and loading. 
Note that the vocechat-server itself is a high-performance HTTP server, and there is no need to install and configure nginx. 
If the 443 port is occupied, you should stop the related services and let the vocechat-server monopolize the 443 port.
