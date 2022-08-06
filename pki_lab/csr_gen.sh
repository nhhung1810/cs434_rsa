#!/bin/bash

openssl req -newkey rsa:2048 -sha256 \
-keyout server.key -out server.csr \
-subj "/CN=www.example.com/O=CompSec Inc./C=US" \
-passout pass:dees \
-addext "subjectAltName = DNS:www.example.com"
