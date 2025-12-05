# 🌍 ipip.dev - 基于 OpenResty 的 IP 信息查询服务

本仓库包含 **https://ipip.dev** 使用的 IP 查询服务的源代码。

基于 **OpenResty**（Nginx + Lua）实现。

## ✨ 主要功能

* **IP 查询:** 整合 GeoIP2 数据库，提供国家、地区、城市、时区、经纬度、ISP 和 ASN 等全面的地理位置信息。
* **代理检测:** 集成 IP2Proxy，用于识别代理、VPN 或 Tor 等连接类型。
* **API 接口:** 提供多种 API 端点（如 `/json`、`/country`、`/ip`），方便以 JSON 或纯文本格式获取数据，易于集成。
* **AWS 支持:** 部署在 AWS CloudFront 后时，可选择使用 `CloudFront-Viewer-*` 头部信息进行地理定位。

## ⚙️ 先决条件和配置

该服务依赖特定的第三方 Lua 库和 IP 数据库。

### Lua 依赖库

OpenResty Lua 库：

* `anjia0532/lua-resty-maxminddb` ( GeoIP2 查询)
* `ip2location/ip2proxy-resty` ( ip2location 代理检测)
* `xiangnanscu/lua-resty-ipmatcher` （ 判断 ip 地址类型）
* `bungle/lua-resty-template` （ html 模板渲染 ）

### 🗺️ IP 数据库配置

需要在 `init.lua` 中配置以下数据库的路径：

1.  **GeoIP2 (MaxMind):** 用于标准的地理信息查询（国家、城市、ISP/ASN）。
    * `city = "/var/www/html/ipdb/GeoLite2-City.mmdb"`
    * `asn = "/var/www/html/ipdb/GeoLite2-ASN.mmdb"`
2.  **IP2Proxy:** 用于代理/安全检查。
    * `ip2proxy = ip2proxydb:open("/var/www/html/ipdb/IP2PROXY-LITE-PX12.BIN")`

**注意:** 参考 nginx conf文件， 必须将 html 目录和 ipdb目录中的文件路径替换为实际位置，并确保符合 MaxMind 和 IP2Proxy 的相关许可要求。

## 🔗 English / 英文 README

* [**README_en.md**](README_en.md)