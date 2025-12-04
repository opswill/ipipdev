#!/bin/bash

podman build -f Dockerfile -t openresty:latest

podman container rm -f openresty

podman run -d \
    --name openresty \
    --network host \
    --hostname openresty \
    -v  /root/ipip.dev/conf:/etc/nginx/conf.d  \
    -v  /root/ipip.dev/html:/var/www/html  \
    -v  /root/ipip.dev/ipdb:/var/www/html/ipdb  \
    localhost/openresty:latest
