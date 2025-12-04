FROM docker.io/openresty/openresty:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y  apt-utils \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openresty-opm

RUN echo " ... installing system packages dependences ..." \
    && apt-get install -y libmaxminddb-dev \
    && apt-get install -y telnet \
    && apt-get install -y inetutils-ping \
    && apt-get install -y dnsutils \
    && apt-get install -y unzip \
    && apt-get install -y make \
    && apt-get install -y gcc

RUN echo " ... installing opm packages dependences ..." \
    && opm get xiangnanscu/lua-resty-ipmatcher \
    && opm get bungle/lua-resty-template \
    && opm get ip2location/ip2proxy-resty \
    && opm get anjia0532/lua-resty-maxminddb

CMD ["/usr/bin/openresty", "-g", "daemon off;"]

# Use SIGQUIT instead of default SIGTERM to cleanly drain requests
# See https://github.com/openresty/docker-openresty/blob/master/README.md#tips--pitfalls
STOPSIGNAL SIGQUIT
