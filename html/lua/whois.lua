-- whois.lua
local shared = ngx.shared.ipip
local ipmatcher = shared.ipmatcher

local args = ngx.req.get_uri_args()
local query = args and args.query or ngx.var.arg_query

if query ~= nil and type(query) ~= "string" then
    query = tostring(query)
end

if query then
    query = ngx.unescape_uri(query)
end

if not query or query == "" then
    query = shared.get_client_ip()
end

query = query:gsub("^%s*(.-)%s*$", "%1")
query = query:gsub("^%[(.+)%]$", "%1")

local function validate_and_normalize_query(q)
    -- AS number（AS123、AS12345、12345、123）
    local asn = q:match("^[%s]*[Aa][Ss](%d+)[%s]*$") or q:match("^(%d+)$")
    if asn then
        asn = tonumber(asn)
        if asn >= 1 and asn <= 4294967295 then
            return "asn", "AS" .. asn
        end
    end

    -- CIDR（IPv4/IPv6）
    local cidr = q:match("^([^/]+/[^/]+)$")
    if cidr then
        local ip_part = cidr:match("^([^/]+)")
        if ipmatcher.parse_ipv4(ip_part) or ipmatcher.parse_ipv6(ip_part) then
            return "cidr", cidr
        end
    end

    --  IPv4
    if ipmatcher.parse_ipv4(q) then
        return "ipv4", q
    end

    -- IPv6（::1、2001:db8::1）
    if ipmatcher.parse_ipv6(q) then
        return "ipv6", q
    end

    -- domain
    if q:find("%.") then
        local parts = {}
        for part in q:gmatch("[^%.]+") do
            table.insert(parts, part)
        end
        if #parts >= 2 and (not ipmatcher.parse_ipv4(q)) and (not ipmatcher.parse_ipv6(q)) then
            local domain = parts[#parts-1] .. "." .. parts[#parts]
            return "domain", domain:lower()
        end
    end
    return nil, "invalid query"
end

local qtype, normalized_query = validate_and_normalize_query(query)

if not qtype then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.say("Bad Request: only IPv4/IPv6/CIDR/AS number/domain is allowed")
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end

local function get_whois(server, q)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect(server, 43)
    if not ok then
        ngx.log(ngx.ERR, "connect to whois server failed: ", server, " err:", err)
        return nil
    end
    sock:settimeout(3000)

    local _, err_send = sock:send(q .. "\r\n")
    if err_send then
        sock:close()
        return nil
    end

    local data, err_recv = sock:receive("*a")
    sock:close()
    if err_recv and err_recv ~= "closed" then
        return nil
    end
    return data or ""
end

local function format_whois(text)
    if not text or text == "" then return "No whois data found." end

    local lines = {}
    for line in text:gmatch("[^\r\n]+") do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")

        if not (
            line:match("^[%#%%>]") or
            line:match("^%*%*%*") or
            line:match("For more information") or
            line:match("Please query the appropriate registry")
        ) then
            if line ~= "" then
                table.insert(lines, line)
            end
        end
    end
    return table.concat(lines, "\n")
end

local whois_data

if qtype == "asn" then
    whois_data = get_whois("whois.radb.net", normalized_query)
        or get_whois("whois.ripe.net", "-B " .. normalized_query) 
elseif qtype == "domain" then
    local iana = get_whois("whois.iana.org", normalized_query)
    local server = iana and iana:match("whois%:[%s]*(%S+)")
    if server then
        whois_data = get_whois(server, normalized_query)
    else
        whois_data = iana
    end
else
    -- IP / CIDR
    local iana = get_whois("whois.iana.org", normalized_query)
    local server = iana and iana:match("whois%:[%s]*(%S+)")
    if server then
        whois_data = get_whois(server, normalized_query)
    else
        whois_data = iana
    end
end

ngx.header["Content-Type"] = "text/plain; charset=utf-8"
ngx.say("Query: " .. query .. " → " .. normalized_query .. " [" .. string.upper(qtype) .. "]")
ngx.say(string.rep("=", 80))
ngx.say(format_whois(whois_data))