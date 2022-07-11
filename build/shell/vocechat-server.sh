#!/bin/sh
START=90
STOP=10
RETVAL=0

PWD=`pwd`
WORKDIR=""

cd $WORKDIR
mkdir data/wwwroot
case "$1" in
  start)
    echo -n "Starting vocechat-server:"
    ./vocechat-server config/config.toml --daemon --stdout=data/vocechat-server.log 2>&1
    echo -e "\033[32m [OK] \033[0m"
    ;;
  stop)
    echo -n "Shutting down vocechat-server:"
    kill `pidof vocechat-server` 2>&1
    echo -e "\033[32m [OK] \033[0m"
    RETVAL=$?
    ;;
  restart)
    $0 stop
    $0 start
    RETVAL=$?
    ;;
  log)
    tail -f $WORKDIR/data/vocechat-server.log
    ;;
  *)
    echo "Usage $0 {start|stop|restart}"
    cd $PWD
    exit 1
esac

cd $PWD