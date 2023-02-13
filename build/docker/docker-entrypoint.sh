#!/bin/sh

#uid=${UID:=$(id -u)}
#gid=${GID:=$(id -g)}
#admin_user=${ADMIN_USER:="admin"}
#admin_password=${ADMIN_PASSWORD:="123456"}
#domain=${DOMAIN:=""}
#
#if test ! -z $domain; then
#  sed -i "s/# domain = .*\$/domain = \"$domain\"/ig" /home/vocechat-server/config/config.toml
#fi
#
#if grep -q "name = \"$admin_user\"" /home/vocechat-server/config/config.toml; then
#cat <<EOT >> /home/vocechat-server/config/config.toml
#[[user]]
#name = "$admin_user"
#password = "$admin_password"
#email = "$admin_user@$domain"
#is_admin = true
#EOT
#fi

cd /home/vocechat-server/
cmd="./vocechat-server"
if test $# -gt 0; then
  case "$1" in
      *.toml)
        cmd="./vocechat-server $@"
        break
        ;;
      --*)
        cmd="./vocechat-server $@"
        break
        ;;
      *) cmd="$@";;
  esac
fi
echo $cmd
$cmd
# exec "$cmd"
