-- GeoIP2 Databases: city and asn, modify the path as needed
local geo = require "resty.maxminddb"
if not geo.initted() then
    local ok, err = geo.init({
        city = "/var/www/html/ipdb/GeoLite2-City.mmdb",
        asn = "/var/www/html/ipdb/GeoLite2-ASN.mmdb"
    })

    if not ok then
        ngx.log(ngx.ERR, "Failed to initialize MaxmindDB: ", err or "unknown error")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
end

-- ip2location proxy database, modify the path as needed
local ip2proxydb = require "ip2proxy"
local ip2proxy = ip2proxydb:open("/var/www/html/ipdb/IP2PROXY-LITE-PX12.BIN")

-- Shared modules and functions
local shared = {
    geo = geo,
    ip2proxy = ip2proxy,
    cjson = require "cjson.safe",
    template = require "resty.template",
    ipmatcher = require "resty.ipmatcher",
    resolver = require "resty.dns.resolver",
    dns = require "resty.dns.resolver" 
}

-- Function to get client IP (handles query param or remote_addr)
function shared.get_client_ip()
    local query_ip = ngx.var.arg_query
    if query_ip and query_ip ~= "" then
        return query_ip
    end
    return ngx.var.remote_addr
end

-- Function to determine IP type (IPv4, IPv6, or domain)
function shared.get_ip_type(ip)
    local is_ipv4 = shared.ipmatcher.parse_ipv4(ip)
    if is_ipv4 then return "IPv4" end
    local is_ipv6 = shared.ipmatcher.parse_ipv6(ip)
    if is_ipv6 then return "IPv6" end
    return nil, "true"  -- nil for type, true for is_domain
end

-- Function to resolve domain to IP if needed
function shared.resolve_domain_if_needed(ip)
    local _, is_domain = shared.get_ip_type(ip)
    if not is_domain then return ip end

    local r, err = shared.resolver:new {
        nameservers = {"8.8.8.8", {"1.1.1.1", 53}},
        retrans = 2,
        timeout = 500
    }
    if not r then
        ngx.log(ngx.ERR, "Failed to create resolver: ", err)
        return ip  -- Fallback to original
    end

    local domain_answers, err = r:query(ip, { qtype = r.TYPE_A }, {})
    if domain_answers and #domain_answers > 0 then
        for _, ans in ipairs(domain_answers) do
            if ans.address then
                return ans.address
            end
        end
    end
    return ip
end

-- Function to get PTR hostname
function shared.get_hostname(ip)
    local r, err = shared.resolver:new {
        nameservers = {"8.8.8.8", {"1.1.1.1", 53}},
        retrans = 2,
        timeout = 500
    }
    if not r then return nil end

    local ptr_answers, err = r:reverse_query(ip)
    if ptr_answers and #ptr_answers > 0 then
        return ptr_answers[1].ptrdname
    end
    return nil
end

-- Function to lookup GeoIP2 data
function shared.lookup_geoip2(ip)
    local geocity, err = shared.geo.lookup(ip,nil,"city")
    local geo_data = {}
    if geocity then
        if geocity["country"] then
            geo_data.country_name = geocity["country"]["names"]["en"]
            geo_data.country_code = geocity["country"]["iso_code"]
            geo_data.ineu = geocity["country"]["is_in_european_union"]
        elseif geocity["registered_country"] then
            geo_data.country_name = geocity["registered_country"]["names"]["en"]
        end
        geo_data.continent = geocity["continent"] and geocity["continent"]["names"]["en"]
        geo_data.region_name = geocity["subdivisions"] and geocity["subdivisions"][1]["names"]["en"]
        geo_data.city = geocity["city"] and geocity["city"]["names"]["en"]
        if geocity["location"] then
            geo_data.latitude = geocity["location"]["latitude"]
            geo_data.longitude = geocity["location"]["longitude"]
            geo_data.timezone = geocity["location"]["time_zone"]
            geo_data.metrocode = geocity["location"]["metro_code"]
        end
    end

    local geoasn, err = shared.geo.lookup(ip, nil,"asn")
    if geoasn then
        geo_data.isp = geoasn["autonomous_system_organization"]
        geo_data.asn = geoasn["autonomous_system_number"]
    end

    return geo_data
end

-- Function to check proxy with IP2Proxy
function shared.check_proxy(ip)
    local result = shared.ip2proxy:get_all(ip)
    if result and result["isproxy"] == 1 then
        result.source = "IP2Proxy"
        return "true", result
    end
    return nil
end

-- Function to get AWS CloudFront headers
function shared.get_aws_headers()
    local headers = ngx.req.get_headers()
    return {
        country_name = headers["CloudFront-Viewer-Country-Name"],
        country_code = headers["CloudFront-Viewer-Country"],
        region_code = headers["CloudFront-Viewer-Country-Region"],
        region_name = headers["CloudFront-Viewer-Country-Region-Name"],
        city = headers["CloudFront-Viewer-City"],
        latitude = headers["CloudFront-Viewer-Latitude"],
        longitude = headers["CloudFront-Viewer-Longitude"],
        timezone = headers["CloudFront-Viewer-Time-Zone"],
        metrocode = headers["CloudFront-Viewer-Metro-Code"],
        postalcode = headers["CloudFront-Viewer-Postal-Code"],
        asn = headers["CloudFront-Viewer-ASN"]
    }
end

-- Function to build IP detail object
function shared.build_ip_detail(ip, use_aws)
    local detail = {
        ip = ip,
        version = select(1, shared.get_ip_type(ip)),
        hostname = shared.get_hostname(ip),
        user_agent = ngx.req.get_headers()["user-agent"] or "",  
    }

    local is_proxy, proxy_data = shared.check_proxy(ip)
    detail.proxy = is_proxy
    detail.security = proxy_data

    local geo_data = shared.lookup_geoip2(ip)
    if use_aws then
        local aws = shared.get_aws_headers()
        if aws.country_name then
            detail.country = aws.country_name
            detail.country_iso = aws.country_code
            detail.region_iso = aws.region_code
            detail.region = aws.region_name
            detail.city = aws.city
            detail.latitude = aws.latitude
            detail.longitude = aws.longitude
            detail.timezone = aws.timezone
            detail.metro = aws.metrocode
            detail.zip = aws.postalcode
            detail.asn = aws.asn
            detail.flag = detail.country_iso and shared.get_country_flag_emoji(detail.country_iso)
            detail.source = "AWS"
            return detail
        end
    end

    -- Fallback to GeoIP2
    detail.country = geo_data.country_name
    detail.country_iso = geo_data.country_code
    detail.continent = geo_data.continent
    detail.country_ineu = geo_data.ineu
    detail.region = geo_data.region_name
    detail.city = geo_data.city
    detail.latitude = geo_data.latitude
    detail.longitude = geo_data.longitude
    detail.timezone = geo_data.timezone
    detail.metro = geo_data.metrocode
    detail.asn = geo_data.asn
    detail.isp = geo_data.isp
    detail.flag = detail.country_iso and shared.get_country_flag_emoji(detail.country_iso)
    detail.source = "MaxMind"
    return detail
end

-- Function to check if CLI tool via User-Agent
function shared.is_cli_tool()
    local user_agent = ngx.req.get_headers()["user-agent"] or ""
    local cli_tools = { "curl", "wget", "httpie", "fetch", "go", "mikrotik", "java", "python" }
    local ua_lower = string.lower(user_agent)
    for _, tool in ipairs(cli_tools) do
        if string.match(ua_lower, tool) then
            return true
        end
    end
    return false
end

-- Function to build whois links for template
function shared.build_whois_links(ipinfo)
    local links = {}
    local ip   = ipinfo.ip or ""
    local type = ipinfo.type and string.upper(ipinfo.type) or "IP"

    if ip ~= "" then
        table.insert(links, string.format(
            '<a href="//%s/whois?query=%s" target="_blank" rel="noopener" ' ..
            'title="Whois registration record for this %s address">%s Whois</a>',
            ngx.var.server_name, ip, type, type
        ))
    end

    if ipinfo.asn then
        table.insert(links, string.format(
            '<a href="//%s/whois?query=AS%s" target="_blank" rel="noopener" ' ..
            'title="Autonomous System registry and prefix information">AS%s</a>',
            ngx.var.server_name, ipinfo.asn, ipinfo.asn
        ))
    end

    if ipinfo.hostname then
        local match = ngx.re.match(ipinfo.hostname, "([^.]+\\.[^.]+)$")
        if match and match[1] then
            local domain = match[1]
            table.insert(links, string.format(
                '<a href="//%s/whois?query=%s" target="_blank" rel="noopener" ' ..
                'title="Domain registration record for this IP\'s reverse DNS hostname">%s</a>',
                ngx.var.server_name, domain, domain
            ))
        end
    end

    if ip ~= "" then
        local tools = {
            {url = "https://stat.ripe.net/resource/" .. ip,               name = "RIPEstat",       title = "Authoritative RIPE NCC statistics, BGP, geo & history"},
            {url = "https://bgp.he.net/ip/" .. ip,               name = "HE BGP",         title = "Live BGP route table, announced prefixes and peers"},
            {url = "https://www.abuseipdb.com/check/" .. ip,     name = "AbuseIPDB",      title = "Community-reported abuse confidence score and blacklist status"},
            {url = "https://radar.cloudflare.com/ip/" .. ip,     name = "Cloudflare Radar", title = "Global traffic ranking, threat intel and adoption trends"},
        }

        for _, t in ipairs(tools) do
            table.insert(links, string.format(
                '<a href="%s" target="_blank" rel="noopener noreferrer" title="%s">%s</a>',
                t.url, t.title, t.name
            ))
        end
    end

    return table.concat(links, " <span style='color:#999;font-size:1.2em'>•</span> ")
end

-- function to build country flag emoji from ISO code
function shared.get_country_flag_emoji(iso)
    if not iso or type(iso) ~= "string" or #iso ~= 2 then
        return nil
    end

    local code = string.upper(iso)

    if not shared._flag_cache then
        shared._flag_cache = {}
    end

    local cached = shared._flag_cache[code]
    if cached ~= nil then
        return cached 
    end

    -- Regional Indicator Symbols (A-Z)
    local RI = {
        A = "🇦", B = "🇧", C = "🇨", D = "🇩", E = "🇪", F = "🇫", G = "🇬",
        H = "🇭", I = "🇮", J = "🇯", K = "🇰", L = "🇱", M = "🇲", N = "🇳",
        O = "🇴", P = "🇵", Q = "🇶", R = "🇷", S = "🇸", T = "🇹", U = "🇺",
        V = "🇻", W = "🇼", X = "🇽", Y = "🇾", Z = "🇿"
    }

    local a = RI[code:sub(1,1)]
    local b = RI[code:sub(2,2)]

    if not a or not b then
        shared._flag_cache[code] = nil
        return nil
    end

    local flag = a .. b
    shared._flag_cache[code] = flag
    return flag
end

-- Expose shared to ngx (all Lua files can access via ngx.shared.ipip)
ngx.shared.ipip = shared
