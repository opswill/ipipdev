-- mcp.lua
local shared = ngx.shared.ipip
local cjson  = shared.cjson

local tools = {
    {
        name = "ip_lookup",
        title = "IP Geolocation Lookup",
        description = "Query geolocation, ASN, ISP, hostname, proxy/VPN/hosting  detection for an IP or domain. Leave blank to detect the current visitor's real IP.",
        inputSchema = {
            type = "object",
            properties = {
                query = {
                    type = "string",
                    description = "IP address or domain name (optional, leave empty to use visitor's IP)"
                }
            },
            additionalProperties = false
        }
    },
    {
        name = "whois_lookup",
        title = "WHOIS Lookup",
        description = "Retrieve WHOIS records for domain name, IP address, CIDR block, or ASN. Leave blank to query the WHOIS of the current visitor's IP.",
        inputSchema = {
            type = "object",
            properties = {
                query = {
                    type = "string",
                    description = "Domain name, IP address, CIDR (e.g. 1.1.1.0/24), or ASN (e.g. AS13335). Optional — leave empty to use visitor's IP"
                }
            },
            additionalProperties = false
        }
    }
}

local function get_ipinfo(args)
    local query = (type(args) == "table") and args.query or nil
    local base_ip = shared.get_client_ip()
    local target_ip = (query and query ~= "") and shared.resolve_domain_if_needed(query)
                       or shared.resolve_domain_if_needed(base_ip)

    local info = shared.build_ip_detail(target_ip, target_ip == ngx.var.remote_addr)

    info.latitude  = info.latitude  and tonumber(info.latitude)  or nil
    info.longitude = info.longitude and tonumber(info.longitude) or nil
    if info.asn then info.asn = tostring(info.asn) end

    return info
end

local function get_whois_info(query)
    if not query or query == "" then
        return nil, "Query parameter is required for whois_lookup"
    end

    local res = ngx.location.capture("/whois", {
        args = { query = query },
        method = ngx.HTTP_GET
    })

    if res.status ~= 200 then
        return nil, ("WHOIS service returned status %d"):format(res.status)
    end

    if not res.body or res.body == "" then
        return nil, "Empty response from WHOIS service"
    end

    return res.body, nil
end

if ngx.var.uri ~= "/mcp" or ngx.req.get_method() ~= "POST" then
    return ngx.exit(404)
end

ngx.req.read_body()
local raw = ngx.req.get_body_data() or ""
if raw == "" then
    return ngx.exit(400)
end

local ok, req = pcall(cjson.decode, raw)
if not ok or type(req) ~= "table" then
    return ngx.exit(400)
end

local requests = req.jsonrpc and { req } or req
local responses = {}

for _, r in ipairs(requests) do
    if not (type(r) == "table" and r.jsonrpc == "2.0" and r.id ~= nil and type(r.method) == "string") then
        goto continue
    end

    local result = nil
    local error_obj = nil

    if r.method == "initialize" then
        local pv = (r.params and r.params.protocolVersion) or "unknown"
        result = {
            protocolVersion = pv,
            serverInfo = { name = "IPIP.dev", version = "1.0" },
            capabilities = { tools = { listChanged = true } }
        }

    elseif r.method == "tools/list" then
        result = { tools = tools }

    elseif r.method == "tools/call" and r.params and r.params.name == "ip_lookup" then
        local arguments = r.params.arguments or {}
        local data = get_ipinfo(arguments)
        result = {
            content = {
                {
                    type = "text",
                    text = cjson.encode(data)
                }
            },
            isError = false
        }
    elseif r.method == "tools/call" and r.params and r.params.name == "whois_lookup" then
        local arguments = r.params.arguments or {}
        local input = arguments.query
        local query_to_use = shared.get_client_ip()

        if input ~= nil and input ~= cjson.null then
            if type(input) == "string" then
                if input ~= "" then
                    query_to_use = input
                end
            else
                query_to_use = tostring(input)
            end
        end

        local whois_text, err = get_whois_info(query_to_use)
        if not whois_text then
            result = {
                content = {
                    {
                        type = "text",
                        text = "Error: " .. (err or "Unknown error")
                    }
                },
                isError = true
            }
        else
            local display_text = "WHOIS result for: " .. query_to_use .. "\n\n```whois\n" .. whois_text .. "\n```"
            result = {
                content = {
                    {
                        type = "text",
                        text = display_text
                    }
                },
                isError = false
            }
        end

    else
        error_obj = { code = -32601, message = "Method not found" }
    end

    table.insert(responses, {
        jsonrpc = "2.0",
        id = r.id,
        result = result,
        error = error_obj
    })

    ::continue::
end

ngx.header["Content-Type"] = "application/json; charset=utf-8"
if #responses == 1 then
    ngx.say(cjson.encode(responses[1]))
else
    ngx.say(cjson.encode(responses))
end