#!/bin/sh
# auto-check version requires repo to be public
# VOCECHAT_SERVER_VERION=`curl -s https://github.com/Privoce/vocechat-server/releases/latest | sed "s/.*tag\/\(.*\)\".*/\1/ig"`
VOCECHAT_SERVER_VERION="v0.3.1"
ARCH=`uname -m`
OS=`uname`
PLATFORM="x86_64-unknown-linux-musl"
WORK_DIR=""
BIND_PORT=3000
DOMAIN=""
HTTPS_ON=""
#PWD=`pwd`

echo "  ┌────────────────────────────────────────────────────────────────┐ "
echo "  │              vocechat-server $VOCECHAT_SERVER_VERION installation guide         │ "
echo "  └────────────────────────────────────────────────────────────────┘ "

x_read() {
  read -r $1 < /dev/tty
}



have_command() {
  if command -v $1 >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

check_env() {
  if test "$OS" != "Darwin"; then
    if have_command apt; then
      apt install -y unzip
    fi
  fi
  echo ""
}

error_exit() {
  echo -e "\033[31m$1\033[0m"
  exit
}

sed_replace() {
  if test "$OS" = "Darwin" ; then
    sed -i "" $*
  else
    sed -i $*
  fi
}
random_64() {
  for i in {1..64}
  do
     echo $(( RANDOM % 10 )) | xargs echo -n
  done
}
is_writable()
{
  if test ! -d $1; then
    mkdir -p $1;
  fi
  if test -w $1; then
    return 0
  fi
  return 1
}
port_in_use()
{
  n=`netstat -nlpt|grep ":$1 "|wc -l`
  if test $n -gt 0; then
    return 0
  else
    return 1
  fi
}

input_writable_dir()
{
  WORK_DIR=""
  for workdir in /share/Download ~ `pwd`; do
    if test -d $workdir; then
      workdir2="$workdir/.vocechat-server"
      if is_writable $workdir2; then
        WORK_DIR=$workdir2;
        break;
      fi
    fi
  done
  echo -e "Installation path (Default: \033[31m$WORK_DIR\033[0m):"
  while true; do
    x_read workdir
    if test "$workdir" != ""; then
      WORK_DIR=$workdir
    fi
    if test ! -w $WORK_DIR; then
      echo "$WORK_DIR is unwritable! "
    else
      break
    fi
 done
}

input_domain()
{
  echo "Please input domain (Default empty):"
  x_read DOMAIN
  if test "$DOMAIN" != ""; then
    input_https_on
  fi
}

input_https_on()
{
  echo "Enable HTTPS: [y,n] (Default n)"
  x_read HTTPS_ON
  HTTPS_ON=$(echo $HTTPS_ON|tr [A-Z] [a-z])
  if test "$HTTPS_ON" = "y"; then
    if port_in_use 443; then
      error_exit "Port 443 is in use! Enable SSL requires opening port 443."
    fi
  fi
}

install_as_service()
{
  echo "Start with system launched: [y,n] (Default: n)"
  x_read AS_SERVICE
  if test "$AS_SERVICE" = "y"; then
    if test "$OS" = "Darwin"; then
      cat >> ~/Library/LaunchAgents/com.vocechat.server.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>com.vocechat.server.plist</string>
        <key>ProgramArguments</key>
        <array>
                <string>bin/vocechat-server</string>
                <string>config/config.toml</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
</dict>
</plist>
EOF
    fi
  fi
}

check_env

input_writable_dir

cd $WORK_DIR
if test -d $WORK_DIR/data/db; then
  rm -rf $WORK_DIR/data
fi

input_domain


case $ARCH in
  arm64)
    if test `uname` = "Darwin"; then
      PLATFORM="aarch64-apple-darwin"
    else
      PLATFORM="aarch64-unknown-linux-musl"
    fi
    ;;
  aarch64)
    PLATFORM="aarch64-unknown-linux-musl"
    ;;
  armv7l | arm)
    PLATFORM="armv7-unknown-linux-musleabihf"
    ;;
  x86_64)
    if test `uname` = "Darwin"; then
      PLATFORM="x86_64-apple-darwin"
    else
      PLATFORM="x86_64-unknown-linux-musl"
    fi
    ;;
  *)
    echo -n "error: not supportted arch $(ARCH)!"
    exit
    ;;
esac

echo -e "Detected platform: \033[31m$PLATFORM\033[0m."

BIN_NAME="vocechat-server-$VOCECHAT_SERVER_VERION-$PLATFORM.zip"
BIN_URL="https://s.voce.chat/$BIN_NAME"
echo "Downloading URL: $BIN_URL"

# clear old data:
kill `pidof vocechat-server` 2>/dev/null
if test ! -f vocechat-server.zip; then
  curl --progress-bar -f $BIN_URL -o vocechat-server.zip || exit
fi
unzip -oq vocechat-server.zip || exit
chmod a+x vocechat-server


curl -f "https://s.voce.chat/vocechat-server.sh" -o vocechat-server.sh || exit
if test "$DOMAIN" != ""; then
  sed -i "s/# domain = .*\$/domain = \"$DOMAIN\"/ig" config/config.toml
  echo $HTTPS_ON
  if test "$HTTPS_ON" = "y"; then
    BIND_PORT=443
    sed -i "s/bind = .*\$/bind = \"0.0.0.0:$BIND_PORT\"/ig" config/config.toml
    sed -i ':a;N;$!ba;s/# \[network\.tls\]/[network.tls]/4' config/config.toml
    sed -i ':a;N;$!ba;s/# type = \"acme_tls_alpn_01\"/type = "acme_tls_alpn_01"/1' config/config.toml
    sed -i ':a;N;$!ba;s/# cache_path/cache_path/2' config/config.toml
    mkdir -p $WORK_DIR/data/cert
    # tr '\n' '^' < config/config.toml | sed 's/# \[network\.tls\]/[network.tls]/4' | tr '^' '\n' > config/config2.toml
  fi
fi

sed_replace "s#WORKDIR=.*\$#WORKDIR=\"$WORK_DIR\"#ig" vocechat-server.sh

chmod a+x vocechat-server.sh

if test -d /etc/init.d/; then
  cp -rf vocechat-server.sh /etc/init.d/
  echo "install done! "
  echo "run: /etc/init.d/vocechat-server.sh start|stop|restart"
else
  echo "/etc/init.d/ does not exists, refused! please try Ubuntu or CentOS, you can contact han@privoce.com."
  exit
  # echo "run: /etc/init.d/vocechat-server.sh start|stop|restart"
fi

export PATH=$PATH:$WORK_DIR
echo "export PATH=\$PATH:$WORK_DIR" >> /etc/profile
#cd $PWD
