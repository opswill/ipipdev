-- mcp.lua - ipip.dev OpenResty MCP Streamable HTTP endpoint
-- Supported protocols: 2026-07-28 (stateless), 2025-11-25 (legacy, stateless HTTP)
-- Requires init.lua to have registered ngx.shared.ipip and the internal /whois route.
-- This is a JSON-response-only MCP server: no SSE, subscriptions, tasks or sessions.

local shared = ngx.shared.ipip
local cjson = shared and shared.cjson or require("cjson.safe")
local MODERN = "2026-07-28"
local LEGACY = "2025-11-25"
local SERVER = { name = "IPIP.dev", version = "2.0.0" }
local CACHE_TTL_MS = 300000
local MAX_BODY_BYTES = 65536
local MAX_QUERY_BYTES = 253

-- Origin policy is enforced by nginx for the /mcp location.
-- This handler only validates MCP HTTP metadata and JSON-RPC messages.

local tools = {
	{
		name = "ip_lookup",
		title = "IP Geolocation Lookup",
		description = "Look up IP/domain geolocation, ASN, ISP, hostname and proxy information using ipip.dev's MaxMind/IP2Proxy lookup path. With no query, look up the HTTP caller's IP (possibly an MCP gateway).",
		inputSchema = {
			type = "object",
			properties = {
				query = {
					type = "string",
					description = "IPv4, IPv6, or DNS hostname. Omit for HTTP caller's IP.",
					maxLength = MAX_QUERY_BYTES,
				},
				format = { type = "string", enum = { "json" }, description = "Optional; JSON only." },
			},
			additionalProperties = false,
		},
	},
	{
		name = "whois_lookup",
		title = "WHOIS / RDAP Lookup",
		description = "Look up WHOIS/RDAP for an IP, CIDR, ASN or domain using the existing /whois backend. No query means the HTTP caller's IP.",
		inputSchema = {
			type = "object",
			properties = {
				query = {
					type = "string",
					description = "IP, CIDR, AS13335 or domain. Omit for HTTP caller's IP.",
					maxLength = MAX_QUERY_BYTES,
				},
				format = {
					type = "string",
					enum = { "json", "yaml", "text", "both" },
					description = "Response format; default both. text is an alias of yaml.",
				},
			},
			additionalProperties = false,
		},
	},
}

local function encode(value)
	local data, err = cjson.encode(value)
	if data then
		return data
	end
	ngx.log(ngx.ERR, "MCP JSON encode failed: ", err or "unknown")
	return nil
end

local function json_response(status, object)
	ngx.status = status
	ngx.header["Content-Type"] = "application/json; charset=utf-8"
	ngx.header["Cache-Control"] = "no-store"
	local body = encode(object)
	if not body then
		ngx.status = 500
		ngx.say('{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}')
		return
	end
	ngx.say(body)
end

local function rpc_error(id, code, message, data)
	local e = { code = code, message = message }
	if data ~= nil then
		e.data = data
	end
	return { jsonrpc = "2.0", id = id == nil and cjson.null or id, error = e }
end

local function rpc_result(id, result)
	return { jsonrpc = "2.0", id = id, result = result }
end

local function modern_result(fields)
	fields.resultType = "complete"
	fields._meta = { ["io.modelcontextprotocol/serverInfo"] = SERVER }
	return fields
end

local function trim(s)
	return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function headers_lowercase()
	local headers = ngx.req.get_headers()
	local out = {}
	for key, value in pairs(headers) do
		out[string.lower(key)] = value
	end
	return out
end

local function scalar_header(h, name)
	local v = h[name]
	if v == nil then
		return nil
	end
	if type(v) ~= "string" or v:find("[%c]") then
		return false
	end
	return v
end

local function valid_domain(value)
	if #value > 253 or not value:match("^[%w%.%-_]+%.?$") then
		return false
	end
	local hostname = value:gsub("%.$", "")
	if not hostname:find("%.", 1) then
		return false
	end
	for label in hostname:gmatch("[^.]+") do
		if #label < 1 or #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then
			return false
		end
	end
	if hostname:find("..", 1, true) then
		return false
	end
	return true
end

local function validate_ip_query(q)
	if shared.get_ip_type then
		local t = select(1, shared.get_ip_type(q))
		if t == "IPv4" or t == "IPv6" then
			return true
		end
	end
	return valid_domain(q)
end

local function validated_arguments(params)
	if type(params) ~= "table" or type(params.name) ~= "string" then
		return nil, "params.name must be a string"
	end
	local args = params.arguments
	if args == nil then
		args = {}
	end
	if type(args) ~= "table" then
		return nil, "arguments must be an object"
	end
	for key, _ in pairs(args) do
		if key ~= "query" and key ~= "format" then
			return nil, "Unknown argument: " .. tostring(key)
		end
	end
	if args.query ~= nil and (type(args.query) ~= "string" or #args.query > MAX_QUERY_BYTES) then
		return nil, "query must be a string of at most 253 bytes"
	end
	if args.format ~= nil and type(args.format) ~= "string" then
		return nil, "format must be a string"
	end
	return args
end

local function tool_success(content, structured, modern)
	local result = { content = content, isError = false }
	if structured ~= nil then
		result.structuredContent = structured
	end
	return modern and modern_result(result) or result
end

local function tool_failure(message, modern)
	local result = {
		content = { { type = "text", text = "Error: " .. tostring(message) } },
		isError = true,
	}
	return modern and modern_result(result) or result
end

local function do_ip_lookup(args, modern)
	if args.format ~= nil and args.format ~= "json" then
		return tool_failure("ip_lookup supports only format=json", modern)
	end
	local explicit = args.query ~= nil and trim(args.query) ~= ""
	local query = explicit and trim(args.query) or ""
	-- Use the site's existing IP resolution / GeoIP2 / IP2Proxy / PTR helpers.
	-- Never use a query-string parameter to override the implicit MCP caller IP.
	local visitor_ip = ngx.var.remote_addr
	if not visitor_ip or visitor_ip == "" then
		return tool_failure("HTTP client IP is unavailable", modern)
	end
	local target = explicit and query or visitor_ip
	if not validate_ip_query(target) then
		return tool_failure("Invalid IP address or domain name", modern)
	end
	local resolved = shared.resolve_domain_if_needed(target)
	if type(resolved) ~= "string" then
		return tool_failure("IP/domain resolution failed", modern)
	end
	local resolved_type = select(1, shared.get_ip_type(resolved))
	if resolved_type ~= "IPv4" and resolved_type ~= "IPv6" then
		return tool_failure("Could not resolve the hostname to an IP address", modern)
	end
	-- Always use ipip.dev's native MaxMind-backed results, for explicit and
	-- implicit lookups alike. The second argument disables CDN metadata override.
	local info = shared.build_ip_detail(resolved, false)
	if type(info) ~= "table" then
		return tool_failure("IP lookup returned no result", modern)
	end
	info.latitude = info.latitude and tonumber(info.latitude) or nil
	info.longitude = info.longitude and tonumber(info.longitude) or nil
	if info.asn ~= nil then
		info.asn = tostring(info.asn)
	end
	info.query = query
	info.ip = resolved
	info.is_me = not explicit
	local cleaned = {}
	for key, value in pairs(info) do
		if value ~= nil and value ~= cjson.null and value ~= "" then
			cleaned[key] = value
		end
	end
	local payload = encode(cleaned)
	if not payload then
		return tool_failure("Could not serialize IP lookup", modern)
	end
	return tool_success({ { type = "text", text = payload } }, cleaned, modern)
end

local function whois_capture(query, format)
	local res = ngx.location.capture("/whois", {
		args = { query = query, format = format },
		method = ngx.HTTP_GET,
	})
	if not res then
		return nil, "WHOIS internal subrequest failed"
	end
	if res.status ~= 200 then
		return nil, "WHOIS service returned HTTP " .. tostring(res.status)
	end
	if not res.body or res.body == "" then
		return nil, "WHOIS service returned an empty response"
	end
	return res.body
end

local function do_whois_lookup(args, modern)
	local query = (args.query and trim(args.query) ~= "") and trim(args.query) or ngx.var.remote_addr
	if type(query) ~= "string" or #query == 0 or #query > MAX_QUERY_BYTES or query:find("[%c]") then
		return tool_failure("Invalid WHOIS query", modern)
	end
	local fmt = (args.format or "both"):lower()
	if fmt == "text" then
		fmt = "yaml"
	end
	if fmt ~= "json" and fmt ~= "yaml" and fmt ~= "both" then
		return tool_failure("format must be json, yaml, text, or both", modern)
	end
	-- The project's whois.lua supports all these formats via one subrequest.
	local body, err = whois_capture(query, fmt)
	if not body then
		return tool_failure(err or "WHOIS lookup failed", modern)
	end

	local structured
	if fmt == "json" then
		local decoded = cjson.decode(body)
		if type(decoded) == "table" then
			structured = decoded
		end
	elseif fmt == "both" then
		-- whois.lua outputs formatted text followed by a fenced JSON document.
		local json_part = body:match("```json%s*\n(.-)%s*\n```%s*$")
		if json_part then
			local decoded = cjson.decode(json_part)
			if type(decoded) == "table" then
				structured = decoded
			end
		end
	end
	if structured and structured.rdap == cjson.null and structured.whois == cjson.null then
		return tool_failure("No WHOIS/RDAP records were returned", modern)
	end
	return tool_success({ { type = "text", text = body } }, structured, modern)
end

local function call_tool(params, modern)
	local args, err = validated_arguments(params)
	if not args then
		return nil, err
	end
	local name = params.name
	if name == "ip_lookup" then
		return do_ip_lookup(args, modern)
	elseif name == "whois_lookup" then
		return do_whois_lookup(args, modern)
	end
	return nil, "Unknown tool: " .. name
end

local function decode_header_name(value)
	if type(value) ~= "string" then
		return nil
	end
	if value:sub(1, 9) == "=?base64?" and value:sub(-2) == "?=" then
		local b64 = value:sub(10, -3)
		if #b64 == 0 or not b64:match("^[%w%+/%=]+$") then
			return nil
		end
		local decoded = ngx.decode_base64(b64)
		if type(decoded) ~= "string" then
			return nil
		end
		return decoded
	end
	-- Mcp-Name is restricted to safely transmitted, unpadded ASCII on the wire.
	if value == "" or value:find("[^\032-\126]") then
		return nil
	end
	if value:sub(1, 1) == " " or value:sub(-1) == " " then
		return nil
	end
	return value
end

local function modern_header_error(req, headers)
	local params = req.params
	local meta = type(params) == "table" and params._meta or nil
	local body_version = type(meta) == "table" and meta["io.modelcontextprotocol/protocolVersion"] or nil
	local hv = scalar_header(headers, "mcp-protocol-version")
	local hm = scalar_header(headers, "mcp-method")
	if not hv or not hm or hv ~= body_version or hm ~= req.method then
		return "MCP-Protocol-Version or Mcp-Method header is missing/mismatched"
	end
	local hn = scalar_header(headers, "mcp-name")
	if req.method == "tools/call" or req.method == "resources/read" or req.method == "prompts/get" then
		local key = req.method == "resources/read" and "uri" or "name"
		local required = type(params) == "table" and params[key] or nil
		local parsed = hn and decode_header_name(hn) or nil
		if type(required) ~= "string" or parsed ~= required then
			return "Mcp-Name header is missing/mismatched"
		end
	elseif hn ~= nil then
		return "Unexpected Mcp-Name header"
	end
	return nil
end

local function dispatch(req, modern)
	local method = req.method
	local params = req.params
	if method == "ping" then
		return {}, nil
	elseif method == "server/discover" and modern then
		return {
			supportedVersions = { MODERN, LEGACY },
			capabilities = { tools = {} },
			ttlMs = CACHE_TTL_MS,
			cacheScope = "public",
		},
			nil
	elseif method == "initialize" and not modern then
		if
			type(params) ~= "table"
			or type(params.protocolVersion) ~= "string"
			or type(params.clientInfo) ~= "table"
			or type(params.capabilities) ~= "table"
		then
			return nil, { code = -32602, message = "Invalid initialize params" }
		end
		-- Legacy protocol negotiation: choose exactly what the server implements.
		return {
			protocolVersion = LEGACY,
			capabilities = { tools = { listChanged = false } },
			serverInfo = SERVER,
		},
			nil
	elseif method == "tools/list" then
		if params ~= nil and type(params) ~= "table" then
			return nil, { code = -32602, message = "Invalid tools/list params" }
		end
		if params and params.cursor ~= nil then
			return nil, { code = -32602, message = "Pagination cursor is not supported" }
		end
		if modern then
			return { tools = tools, ttlMs = CACHE_TTL_MS, cacheScope = "public" }, nil
		end
		return { tools = tools }, nil
	elseif method == "tools/call" then
		local ok, output, error_message = pcall(call_tool, params, modern)
		if not ok then
			ngx.log(ngx.ERR, "MCP tools/call failed: ", tostring(output))
			return tool_failure("Internal tool execution error", modern), nil
		end
		if not output then
			return nil, { code = -32602, message = error_message or "Invalid tool params" }
		end
		return output, nil
	end
	return nil, { code = -32601, message = "Method not found" }
end

-- ---- Streamable HTTP entrypoint ----
if ngx.var.uri ~= "/mcp" then
	return ngx.exit(404)
end
local headers = headers_lowercase()
if ngx.req.get_method() ~= "POST" then
	ngx.header["Allow"] = "POST"
	return ngx.exit(405)
end

local content_type = scalar_header(headers, "content-type")
if
	not content_type
	or not (content_type:lower():match("^application/json%s*$") or content_type:lower():match("^application/json%s*;"))
then
	json_response(415, rpc_error(nil, -32600, "Content-Type must be application/json"))
	return
end

ngx.req.read_body()
local raw = ngx.req.get_body_data()
if not raw then
	local path = ngx.req.get_body_file()
	if path then
		-- Nginx may spool bodies larger than client_body_buffer_size to a file.
		-- Read only MAX_BODY_BYTES + 1 bytes; the path is Nginx-generated.
		local f, open_err = io.open(path, "rb")
		if not f then
			ngx.log(ngx.ERR, "MCP could not read request body file: ", open_err or "unknown")
			json_response(400, rpc_error(nil, -32700, "Could not read JSON request"))
			return
		end
		raw = f:read(MAX_BODY_BYTES + 1)
		f:close()
	end
end
if not raw or raw == "" then
	json_response(400, rpc_error(nil, -32700, "Empty JSON request"))
	return
end
if #raw > MAX_BODY_BYTES then
	json_response(413, rpc_error(nil, -32600, "Request body too large"))
	return
end

local request, parse_error = cjson.decode(raw)
if type(request) ~= "table" then
	json_response(400, rpc_error(nil, -32700, "Parse error"))
	return
end
if
	request.jsonrpc ~= "2.0"
	or type(request.method) ~= "string"
	or (request.id ~= nil and request.id ~= cjson.null and type(request.id) ~= "string" and type(request.id) ~= "number")
	or (request.params ~= nil and type(request.params) ~= "table")
then
	json_response(400, rpc_error(nil, -32600, "Invalid JSON-RPC request"))
	return
end
-- Distinguish the eras by the modern per-request envelope. Never accept an
-- unknown modern version as legacy merely because a header is missing.
local meta = request.params and request.params._meta
local claimed_version = type(meta) == "table" and meta["io.modelcontextprotocol/protocolVersion"] or nil
local version_header = scalar_header(headers, "mcp-protocol-version")
local modern = claimed_version ~= nil
	or version_header == MODERN
	or (version_header ~= nil and version_header ~= LEGACY and request.method ~= "initialize")

if modern then
	local mismatch = modern_header_error(request, headers)
	if mismatch then
		json_response(400, rpc_error(request.id, -32020, "HeaderMismatch: " .. mismatch))
		return
	end
	if claimed_version ~= MODERN then
		json_response(
			400,
			rpc_error(request.id, -32022, "Unsupported protocol version", {
				supported = { MODERN, LEGACY },
				requested = claimed_version,
			})
		)
		return
	end
	if type(meta) ~= "table" or type(meta["io.modelcontextprotocol/clientCapabilities"]) ~= "table" then
		json_response(400, rpc_error(request.id, -32602, "Missing or invalid clientCapabilities in params._meta"))
		return
	end
	local client_info = meta["io.modelcontextprotocol/clientInfo"]
	if
		client_info ~= nil
		and (
			type(client_info) ~= "table"
			or type(client_info.name) ~= "string"
			or type(client_info.version) ~= "string"
		)
	then
		json_response(400, rpc_error(request.id, -32602, "Invalid clientInfo in params._meta"))
		return
	end
else
	-- For legacy HTTP, initialize opens the legacy flow without protocol headers.
	-- Subsequent 2025-11-25 requests may include the negotiated header.
	if version_header ~= nil and version_header ~= LEGACY then
		json_response(
			400,
			rpc_error(request.id, -32022, "Unsupported protocol version", {
				supported = { MODERN, LEGACY },
				requested = version_header,
			})
		)
		return
	end
end

-- Only known legacy notifications are accepted. The 2026-07-28 core defines
-- no client-to-server HTTP notifications.
if request.id == nil then
	if
		not modern and (request.method == "notifications/initialized" or request.method == "notifications/cancelled")
	then
		ngx.status = 202
		return
	end
	json_response(400, rpc_error(nil, -32600, "Unsupported notification"))
	return
end

local result, err = dispatch(request, modern)
if err then
	local status = (modern and err.code == -32601) and 404 or 200
	json_response(status, rpc_error(request.id, err.code, err.message, err.data))
	return
end
if modern then
	result = modern_result(result)
end
json_response(200, rpc_result(request.id, result))
