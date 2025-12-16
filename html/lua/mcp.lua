-- mcp.lua
local shared = ngx.shared.ipip
local cjson = shared.cjson

local tools = {
  {
    name = "ip_lookup",
    title = "IP Geolocation Lookup",
    description = "Query geolocation, ASN, ISP, hostname, proxy/VPN/hosting detection for an IP or domain. Leave blank to detect the current visitor's real IP.",
    inputSchema = {
      type = "object",
      properties = {
        query = {
          type = "string",
          description = "IP address or domain name (optional, leave empty to use visitor's IP)"
        },
        format = {
          type = "string",
          description = "Output format: json"
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
          description = "Domain (registrable eTLD+1, e.g., example.com or example.co.uk), IP address, CIDR (e.g., 1.1.1.0/24), or     ASN (e.g., AS13335). For domains, the client should normalize subdomains to the registrable root domain (eTLD+1) before calling this API. Optional — if omitted or empty, the server will use the visitor's IP address."
        },
        format = {
          type = "string",
          description = "Output format: json \n yaml \n both (default: both)"
        }
      },
      additionalProperties = false
    }
  }
}

-- ==== helpers ====
local function to_string(v)
  if v == nil or v == cjson.null then return "" end
  if type(v) == "string" then return v end
  if type(v) == "number" or type(v) == "boolean" then return tostring(v) end
  return cjson.encode(v)
end

local function get_ipinfo(args)
  local query = (type(args) == "table") and args.query or nil
  local base_ip = shared.get_client_ip()
  local target_ip = (query and query ~= "") and shared.resolve_domain_if_needed(query)
    or shared.resolve_domain_if_needed(base_ip)
  local info = shared.build_ip_detail(target_ip, target_ip == ngx.var.remote_addr)
  info.latitude = info.latitude and tonumber(info.latitude) or nil
  info.longitude = info.longitude and tonumber(info.longitude) or nil
  if info.asn then info.asn = tostring(info.asn) end
  -- include input echo for clarity
  info.query = query or ""
  info.ip = target_ip
  info.is_me = (target_ip == ngx.var.remote_addr)
  return info
end

local function prune_nonempty(tbl)
  if type(tbl) ~= "table" then return tbl end
  local out = {}
  for k, v in pairs(tbl) do
    if v ~= nil and v ~= "" and v ~= cjson.null then
      if type(v) == "table" then
        local sub = prune_nonempty(v)
        local keep = false
        if next(sub) ~= nil then keep = true end
        if not keep and type(sub) == "table" and #sub and #sub > 0 then keep = true end
        if keep then out[k] = sub end
      else
        out[k] = v
      end
    end
  end
  return out
end

local function get_whois_body(query, format)
  local res = ngx.location.capture("/whois", {
    args = { query = query, format = format },
    method = ngx.HTTP_GET
  })
  if res.status ~= 200 then
    return nil, string.format("WHOIS service returned status %d", res.status)
  end
  if not res.body or res.body == "" then
    return nil, "Empty response from WHOIS service"
  end
  return res.body, nil
end

-- ==== JSON-RPC endpoint ====
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
    -- ignore format preference; return raw JSON text for MCP tool server
    local data = get_ipinfo(arguments)
    local pruned = prune_nonempty(data)
    local okj, json_str = pcall(cjson.encode, pruned)
    if not okj then json_str = "{}" end
    result = { content = { { type = "text", text = json_str } }, isError = false }

  elseif r.method == "tools/call" and r.params and r.params.name == "whois_lookup" then
    local arguments = r.params.arguments or {}
    local input = arguments.query
    local fmt = (arguments.format and tostring(arguments.format):lower()) or "both"
    if fmt ~= "json" and fmt ~= "yaml" and fmt ~= "text" and fmt ~= "both" then fmt = "both" end
    if fmt == "text" then fmt = "yaml" end

    local query_to_use = shared.get_client_ip()
    if input ~= nil and input ~= cjson.null then
      if type(input) == "string" then
        if input ~= "" then query_to_use = input end
      else
        query_to_use = tostring(input)
      end
    end

    local content = {}
    local yaml_text, json_text
    if fmt == "yaml" or fmt == "both" then
      yaml_text = select(1, get_whois_body(query_to_use, "yaml"))
      if yaml_text then table.insert(content, { type = "text", text = yaml_text }) end
    end
    if fmt == "json" or fmt == "both" then
      json_text = select(1, get_whois_body(query_to_use, "json"))
      if json_text then table.insert(content, { type = "text", text = json_text }) end
    end

    if #content == 0 then
      local _, err = get_whois_body(query_to_use, fmt)
      result = { content = { { type = "text", text = "Error: " .. (err or "Unknown error") } }, isError = true }
    else
      result = { content = content, isError = false }
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
en