#!/bin/bash

# Create private key file
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -pkeyopt rsa_keygen_pubexp:65537 | \
    openssl pkcs8 -topk8 -nocrypt -outform pem > voce.chat.key

# generate CSR file
openssl req -subj "/C=US/ST=Arizona/L=Scottsdale/O=Vocechat,Inc./CN=voce.chat/emailAddress=api.privoce@gmail.com" \
    -new -days 3650 -key voce.chat.key -out voce.chat.csr

# generate self-sign file
openssl x509 -signkey voce.chat.key -in voce.chat.csr -req -days 365 -out voce.chat.crt

# view certificate
openssl req -text -noout -verify -in voce.chat.csr