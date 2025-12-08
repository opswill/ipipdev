local shared = ngx.shared.ipip
local cjson  = shared.cjson

local args        = ngx.req.get_uri_args()
local query_param = args.query and ngx.unescape_uri(args.query) or nil

local target_ip
if query_param then
    target_ip = shared.resolve_domain_if_needed(query_param)
else
    target_ip = shared.get_client_ip()
    target_ip = shared.resolve_domain_if_needed(target_ip)
end

local use_aws = (target_ip == ngx.var.remote_addr)
local ipinfo  = shared.build_ip_detail(target_ip, use_aws)

local uri = ngx.var.uri 

if uri == "/json" or uri == "/json/" then
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say(cjson.encode(ipinfo))
    return ngx.exit(200)
end

if uri == "/proxy" or uri == "/proxy/" then
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    if ipinfo.security then
        ngx.say(cjson.encode(ipinfo.security))
    else
        ngx.say("")
    end
    return ngx.exit(200)
end

local single_fields = {
    ip           = true, continent  = true, country     = true,
    country_iso  = true, region     = true, region_iso  = true,
    city         = true, latitude   = true, longitude   = true,
    metro        = true, zip        = true, timezone    = true,
    asn          = true, hostname   = true, type        = true,
    proxy        = true, isp        = true,  
}

local field = uri:match("^/([^/%?]+)")
if field then
    if single_fields[field] then
        ngx.header["Content-Type"] = "text/plain; charset=utf-8"
        ngx.say(ipinfo[field] or "")
        return ngx.exit(200)
    else
        return ngx.exit(404)
    end
end

if shared.is_cli_tool() then
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.say(target_ip)
    return ngx.exit(200)
end

ngx.header["Content-Type"] = "text/html; charset=utf-8"

shared.template.render("index.html", {
    Host      = ngx.var.server_name,
    IP        = ipinfo.ip,
    Latitude  = ipinfo.latitude,
    Longitude = ipinfo.longitude,

    {Show = "Prefer IP Type", Value = ipinfo.type},
    {Show = "Continent",      Value = ipinfo.continent},
    {Show = "Country",        Value = ipinfo.country},
    {Show = "Country (ISO)",  Value = ipinfo.country_iso},
    {Show = "In EU",          Value = ipinfo.country_ineu},
    {Show = "Region",         Value = ipinfo.region},
    {Show = "Region (ISO)",   Value = ipinfo.region_iso},
    {Show = "City",           Value = ipinfo.city},
    {Show = "Metro Code",     Value = ipinfo.metro},
    {Show = "ZIP Code",       Value = ipinfo.zip},
    {Show = "Timezone",       Value = ipinfo.timezone},
    {Show = "Latitude",       Value = ipinfo.latitude},
    {Show = "Longitude",      Value = ipinfo.longitude},
    {Show = "ASN",            Value = ipinfo.asn},
    {Show = "ISP",            Value = ipinfo.isp},
    {Show = "Hostname",       Value = ipinfo.hostname},
    {Show = "User Agent",     Value = ngx.req.get_headers()["user-agent"] or ""},
    {Show = "Proxy",          Value = ipinfo.proxy},
    {Show = "Whois",          Value = shared.build_whois_links(ipinfo)},
    
    ipinfo    = ipinfo,
    JSON = cjson.encode(ipinfo)
})
