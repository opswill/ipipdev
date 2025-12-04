local query = ngx.var.arg_query
if not query or query == "" then
    return ngx.exit(400)
end

local function get_whois(server, q)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect(server, 43)
    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to whois server: ", err)
        return nil
    end
    sock:settimeout(1000)
    local bytes, err = sock:send(q .. "\r\n")
    if not bytes then
        sock:close()
        return nil
    end
    local data, err = sock:receive("*a")
    sock:close()
    if err then return nil end
    return data
end

local function format_whois(text)
    if not text then return "" end
    text = text:gsub("For%s+more%s+information%s+.+", "")
    text = text:gsub("^%s+", ""):gsub("%s+$", ""):gsub("[\r\n]+[%s]*", "\n")
    local lines = {}
    for line in text:gmatch("[^\r\n]+") do
        if not line:match("^[#%%]") then
            table.insert(lines, line)
        end
    end
    return table.concat(lines, "\n")
end

-- Get whois server from IANA
local iana_data = get_whois("whois.iana.org", query)
local whois_server = iana_data and string.match(iana_data, "whois:%s+(%S+)")

-- Query actual whois
local whois_data = whois_server and get_whois(whois_server, query) or iana_data
ngx.say(format_whois(whois_data) or "No whois data found")
