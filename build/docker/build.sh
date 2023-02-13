#!/bin/bash

cd ../../

#alias rust-musl-builder='docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder'
#rust-musl-builder cargo build --release
docker run --rm -it -v "$(pwd)":/home/rust/src ekidd/rust-musl-builder cargo build --release

if [ -f ./target/x86_64-unknown-linux-musl/release/vocechat-server ]; then

  cp -rf ./target/x86_64-unknown-linux-musl/release/vocechat-server build/docker/vocechat-server
  cp -rf config build/docker/

  cd build/docker

  # sudo docker login -u vocechat -p xxxxxx
  # build arm64
  sudo docker build --platform=linux/amd64 -t vocechat-server:latest .
  docker tag vocechat-server:latest Privoce/vocechat-server:latest
  docker push Privoce/vocechat-server:latest

  # build arrch64
  cp -rf ./target/aarch64-unknown-linux-musl/release/vocechat-server build/docker/vocechat-server
  sudo docker build --platform=linux/arm64 -t vocechat-server:latest-arm64 .
  docker tag vocechat-server:latest-arm64 Privoce/vocechat-server:latest-arm64
  docker push Privoce/vocechat-server:latest-arm64
  #rm -rf  ./config

fi