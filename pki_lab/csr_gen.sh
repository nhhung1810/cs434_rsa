#!/bin/bash

openssl req -newkey rsa:2048 -sha256 \
-keyout server.key -out server.csr \
-subj "/CN=www.hunghuy2022.com/O=CompSec Inc./C=US" \
-passout pass:dees \
-addext "subjectAltName = DNS:www.hunghuy2022.com, \
DNS:www.hunghuy2022A.com, \
DNS:www.hunghuy2022B.com"
