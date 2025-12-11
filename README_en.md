# 🌍 ipip.dev - OpenResty IP Geolocation Service

This repository contains the source code for the IP geolocation and lookup service running at **https://ipip.dev**.

It is implemented using **OpenResty** (nginx with Lua) for high performance, utilizing Lua scripts for logic and templating.

## ✨ Features

* **IP Lookup:** Displays the client's public IP address.
* **Geolocation Details:** Provides comprehensive details like Country, Region, City, Timezone, Latitude/Longitude, ISP, and ASN by leveraging GeoIP2 databases.
* **Proxy Detection:** Integrates with IP2Proxy for identifying proxy, VPN, or Tor connections.
* **Domain Resolution & Hostname:** Supports looking up domains (resolves to IP) and performing reverse DNS (PTR) lookups for hostnames.
* **API Endpoints:** Offers various API endpoints to fetch data in JSON or plain text format for easy integration (e.g., `/json`, `/country`, `/ip`).
* **AWS Support:** Can optionally use `CloudFront-Viewer-*` headers for geolocation if deployed behind AWS CloudFront.

## 🛠️ MCP Tool Server (New!)

ipip.dev now provides a native **MCP (Model Context Protocol)** server that can be used directly inside any MCP-compatible editor or AI assistant (Cursor, Windsurf, Continue.dev, SiliconFlow, etc.).

### Available Tools

| Tool            | Description                                                                                 | Example Usage                                    |
|-----------------|---------------------------------------------------------------------------------------------|--------------------------------------------------|
| `ip_lookup`     | IP or domain geolocation lookup (domains are automatically resolved to IPv4)<br>Returns country, region, city, ASN, ISP and all other fields<br>Leave empty to query your current IP | `@ip_lookup 1.1.1.1`<br>`Where is my IP?`        |
| `whois_lookup`  | Raw WHOIS query for domains, IPs, CIDR blocks, or ASNs<br>Returns the complete original record from the registrar/RIR<br>Leave empty to query WHOIS of your current IP | `@whois_lookup google.com`<br>`WHOIS for AS13335` |

### How to Use

- Only **Streamable HTTP** transport is supported (used by nearly all MCP clients).
- Add the URL as a remote MCP server in your editor/assistant.
- Call tools with `@ip_lookup` / `@whois_lookup` or simply describe what you need in natural language.

## ⚙️ Prerequisites and Setup

The service relies on specific third-party Lua libraries and IP databases.

### Lua Dependencies

The following OpenResty Lua libraries are required and initialized in `init.lua`:

* `anjia0532/lua-resty-maxminddb` (for GeoIP2 lookups)
* `ip2location/ip2proxy-resty` (for proxy detection)
* `xiangnanscu/lua-resty-ipmatcher`
* `bungle/lua-resty-template`

### 🗺️ IP Databases

The `init.lua` file requires the following databases to be configured:

1.  **GeoIP2 (MaxMind):** Used for standard geolocation (Country, City, ISP/ASN).
    * `city = "/var/www/html/ipdb/GeoLite2-City.mmdb"`
    * `asn = "/var/www/html/ipdb/GeoLite2-ASN.mmdb"`
2.  **IP2Proxy:** Used for proxy/security checks.
    * `ip2proxy = ip2proxydb:open("/var/www/html/ipdb/IP2PROXY-LITE-PX12.BIN")`

**Note:** You must replace the file paths in `init.lua` with the actual location of your database files and ensure the necessary MaxMind and IP2Proxy license requirements are met.

## 🔗 Chinese / 中文 README

* [**README_zh.md**](README_zh.md)