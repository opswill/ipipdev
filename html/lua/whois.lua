-- whois.lua
local shared = ngx.shared.ipip
local cjson = shared.cjson
local ipmatcher = shared.ipmatcher
local cache = ngx.shared.ipip_cache
local http = require "resty.http"
local socket = ngx.socket.tcp
local bit = require "bit"

-- 1) Query & type detection
local args = ngx.req.get_uri_args()
local query = args.query or args.arg_query or ""
if type(query) ~= "string" then query = tostring(query) end
if query == "" then
  query = (ngx.shared.ipip and ngx.shared.ipip.get_client_ip and ngx.shared.ipip.get_client_ip())
    or ngx.var.remote_addr or ""
end
query = query:gsub("^%s*(.-)%s*$", "%1"):gsub("^%[(.+)%]$", "%1")

local function is_ipv4(s) return ipmatcher.parse_ipv4(s) and true end
local function is_ipv6(s) return ipmatcher.parse_ipv6(s) and true end

local qtype, target
do
  local s = query
  local lower = s:lower()
  -- ASN
  local asn = s:match("^[Aa][Ss]%s*(%d+)$") or s:match("^(%d+)$")
  if asn then
    local n = tonumber(asn)
    if n and n >= 1 and n <= 4294967295 then qtype, target = "asn", "AS"..n end
  end
  -- CIDR
  if not qtype and s:find("/", 1, true) then
    local ip = s:match("^([^/]+)")
    if ip and (is_ipv4(ip) or is_ipv6(ip)) then qtype, target = (ip:find(":",1,true) and "ipv6" or "ipv4"), s end
  end
  -- IP
  if not qtype then
    if is_ipv4(s) then qtype, target = "ipv4", s
    elseif is_ipv6(s) then qtype, target = "ipv6", s end
  end
  -- Domain
  if not qtype then
    if lower:find("%.") and not lower:find("^%-") and not lower:find("%-$")
       and not lower:find("^%.")
       and not ipmatcher.parse_ipv4(lower) and not ipmatcher.parse_ipv6(lower)
       and lower:match("^[a-z0-9%-%._]+$")
       and lower:match("%.[a-z][a-z%-]*[a-z]$") then
      qtype, target = "domain", lower
    end
  end
end

if not qtype then
  ngx.status = 400
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"
  ngx.say("400 Bad Request: only IPv4/IPv6/CIDR/AS number/domain allowed")
  return ngx.exit(400)
end

-- 2) HTTP / cache / WHOIS
local DEFAULT_BOOTSTRAP_TTL = 259200 -- 3 days
local function http_get(url, timeout)
  local client = http.new(); client:set_timeout(timeout or 6000)
  local res, err = client:request_uri(url, {
    method = "GET",
    headers = { Accept="application/rdap+json", ["User-Agent"]="ipip.dev-whois/1.9.3" },
    ssl_verify = false,
  })
  if not res then return nil, err end
  if res.status >= 200 and res.status < 400 then return res.body, res.status, res.headers end
  return nil, "http "..res.status
end

local function fetch_bootstrap(url)
  local key = "rdap.bs:"..url
  if cache then
    local val = cache:get(key)
    if val then return val, "cache" end
  end
  local body, err = http_get(url)
  if not body then return nil, err end
  if cache then cache:set(key, body, DEFAULT_BOOTSTRAP_TTL) end
  return body, "network"
end

local function whois_query(server, q)
  local sock = socket(); sock:settimeout(4000)
  local ok, err = sock:connect(server, 43); if not ok then return nil, "connect: "..err end
  sock:send(q.."\r\n")
  local t = {}
  while true do
    local line = sock:receive("*l"); if not line then break end
    t[#t+1] = line
  end
  sock:close()
  return table.concat(t, "\n")
end

local function extract_referral_server(iana_text)
    if not iana_text then return nil end
    local srv = iana_text:match("[Rr][Ee][Ff][Ee][Rr]%s*:%s*(%S+)")
    if srv then return srv end

    srv = iana_text:match("[Ww][Hh][Oo][Ii][Ss]%s*:%s*(%S+)")
    if srv then return srv end

    return nil
end

local function whois_fallback_with_referral(qtype, normalized_query)
  if qtype == "asn" then
    local w = whois_query("whois.radb.net", normalized_query)
    if not w then
      w = whois_query("whois.ripe.net", "-B " .. normalized_query)
    end
    return w, "WHOIS (port43: RADB/RIPE)"
  else
    local iana = whois_query("whois.iana.org", normalized_query)
    local srv = extract_referral_server(iana)
    if srv then
      local w2 = whois_query(srv, normalized_query)
      if w2 and #w2 > 0 then
        return w2, ("WHOIS (port43: %s)"):format(srv)
      else
        return iana, "WHOIS (port43: IANA referral failed; using IANA)"
      end
    else
      return iana, "WHOIS (port43: IANA; no referral)"
    end
  end
end

local function clean_whois(text)
  if not text or text == "" then return "No WHOIS data." end
  local out = {}
  for line in text:gmatch("[^\r\n]+") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and not (line:match("^[#%%>]") or line:match("^%*%*%*")
      or line:match("more information") or line:match("query the whois")) then
      out[#out+1] = line
    end
  end
  return #out > 0 and table.concat(out, "\n") or "No meaningful WHOIS data."
end

-- 3) CIDR match & longest prefix
local function ipv4_in_cidr(ip, cidr)
  local addr = ipmatcher.parse_ipv4(ip); if not addr then return false end
  local net, bits = cidr:match("^([^/]+)/(%d+)$"); bits = tonumber(bits)
  if not net or not bits or bits > 32 then return false end
  local base = ipmatcher.parse_ipv4(net); if not base then return false end
  local mask = bit.bnot(bit.rshift(0xFFFFFFFF, bits))
  return bit.band(addr, mask) == bit.band(base, mask), bits
end

local function ipv6_in_cidr(ip, cidr)
  local addr = ipmatcher.parse_ipv6(ip); if not addr then return false end
  local net, bits = cidr:match("^([^/]+)/(%d+)$"); bits = tonumber(bits)
  if not net or not bits or bits > 128 then return false end
  local base = ipmatcher.parse_ipv6(net); if not base then return false end
  local full, rem = math.floor(bits/32), bits%32
  for i=1,full do if addr[i] ~= base[i] then return false end end
  if rem>0 then
    local mask = bit.bnot(bit.rshift(0xFFFFFFFF, rem))
    if bit.band(addr[full+1], mask) ~= bit.band(base[full+1], mask) then return false end
  end
  return true, bits
end

local function ip_in_cidr(ip, cidr) return (ip:find(":") and ipv6_in_cidr or ipv4_in_cidr)(ip, cidr) end

local function select_service_url_from_bootstrap(bs, qtype0, key)
  if not bs or not bs.services then return nil end
  local best_url, best_mask = nil, -1
  for _, svc in ipairs(bs.services) do
    local patterns, urls = svc[1], svc[2]
    local url = urls and urls[1]
    if url then
      for _, pat in ipairs(patterns) do
        if qtype0 == "domain" then
          if pat:lower() == tostring(key):lower() then return url end
        elseif qtype0 == "asn" then
          local s,e = pat:match("^(%d+)%-?(%d+)$"); s = tonumber(s); e = tonumber(e or s)
          if s and e and key >= s and key <= e then return url end
        else
          local ok, mask = ip_in_cidr(key, pat)
          if ok and mask > best_mask then best_url, best_mask = url, mask end
        end
      end
    end
  end
  return best_url
end

-- 4) RDAP query (bootstrap + redirect fallback)
local function query_rdap(qt, tgt)
  local bootstrap_url, endpoint, match_key
  if qt == "domain" then
    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    endpoint = "domain/"..tgt
    match_key = tgt:match("%.[^%.]+$") or ""
  elseif qt == "asn" then
    bootstrap_url = "https://data.iana.org/rdap/asn.json"
    endpoint = "autnum/"..(tgt:gsub("^AS",""))
    local num_str = tgt:match("^AS(%d+)") or tgt
    match_key = tonumber(num_str) or 0
  else
    local ip = tgt:match("^([^/]+)") or tgt
    bootstrap_url = ip:find(":") and "https://data.iana.org/rdap/ipv6.json" or "https://data.iana.org/rdap/ipv4.json"
    endpoint = "ip/"..tgt
    match_key = ip
  end

  local body = select(1, fetch_bootstrap(bootstrap_url))
  if body then
    local bs = cjson.decode(body)
    local base = select_service_url_from_bootstrap(bs, qt, match_key)
    if base then
      local url = base:gsub("/?$","/")..endpoint
      local data = select(1, http_get(url))
      if data then
        local obj = cjson.decode(data)
        if obj then return obj, "RDAP (IANA bootstrap)", base:gsub("/?$","/")..endpoint end
      end
    end
  end

  local function try_redirect(base)
    local uri = base:gsub("/?$","/")..endpoint
    local client = http.new(); client:set_timeout(6000)
    local res = select(1, client:request_uri(uri, {
      method="GET",
      headers={ Accept="application/rdap+json", ["User-Agent"]="ipip.dev-whois/1.9.3" },
      ssl_verify=false, keepalive=false,
    }))
    if not res then return nil end
    if res.status>=300 and res.status<400 and res.headers and res.headers["Location"] then
      local loc = res.headers["Location"]
      local r2 = select(1, client:request_uri(loc, {
        method="GET", headers={ Accept="application/rdap+json", ["User-Agent"]="ipip.dev-whois/1.9.3" }, ssl_verify=false
      }))
      if r2 and r2.status>=200 and r2.status<400 and r2.body then
        local obj = cjson.decode(r2.body); if obj then return obj, base.." redirect", loc end
      end
    elseif res.status>=200 and res.status<300 and res.body then
      local obj = cjson.decode(res.body); if obj then return obj, base, uri end
    end
    return nil
  end

  local obj, src, link = try_redirect("https://rdap.org/")
  if obj then return obj, "RDAP ("..src..")", link end
  obj, src, link = try_redirect("https://rdap-bootstrap.arin.net/bootstrap/")
  if obj then return obj, "RDAP ("..src..")", link end
  return nil, "RDAP failed", nil
end

-- 5) YAML rendering helpers
local LABELS = {
  objectClassName="Object Class", handle="Handle",
  ldhName="LDH Name", unicodeName="Unicode Name", port43="WHOIS (Port43)",
  country="Country", status="Status",
  nameservers="Name Servers", secureDNS="DNSSEC",
  startAddress="IP Range Start", endAddress="IP Range End", ipVersion="IP Version",
  name="Network Name", type="Network Type", parentHandle="Parent Handle",
  startAutnum="ASN Range Start", endAutnum="ASN Range End",
  rdapConformance="RDAP Conformance", lang="Language",
  notices="Notices", remarks="Remarks", links="Links",
  variants="Variants", publicIds="Public IDs"
}
local function L(k) return LABELS[k] or k end
local function S(v) return (v==nil or v==cjson.null) and "" or tostring(v) end

local EVENT_NAME = {
  registration="Registered", reregistration="Re-registered", expiration="Expires",
  deletion="Deleted", reinstatement="Reinstated",
  ["last changed"]="Last Changed", ["last update of rdap database"]="RDAP DB Updated"
}
local function nice_event(a) return (a and (EVENT_NAME[a:lower()] or a:gsub("_"," "):gsub("^%l", string.upper))) or "Event" end

-- buffered output
local buf = {}
local function out(line) buf[#buf+1] = line end

-- YAML emitters
local function y_emit(k, v, indent)
  indent = indent or 0
  local pad = string.rep("  ", indent)
  if v == nil or v == cjson.null then return end
  if type(v) == "table" then
    out(string.format("%s%s:", pad, L(k)))
    for kk,vv in pairs(v) do
      y_emit(kk, vv, indent+1)
    end
  else
    out(string.format("%s%s: %s", pad, L(k), S(v)))
  end
end

local function y_list(k, arr, indent)
  indent = indent or 0
  local pad = string.rep("  ", indent)
  if type(arr) ~= "table" or #arr == 0 then return end
  out(string.format("%s%s:", pad, L(k)))
  for _, x in ipairs(arr) do
    if type(x) == "table" then
      out(pad .. "  -")
      for kk, vv in pairs(x) do
        y_emit(kk, vv, indent+2)
      end
    else
      out(string.format("%s  - %s", pad, S(x)))
    end
  end
end

local function section(title, indent)
  indent = indent or 0
  local pad = string.rep("  ", indent)
  out(string.format("%s%s:", pad, title))
end

local function pick_jcard(item)
  if type(item) ~= "table" then return nil end
  local vtype, v = item[3], item[4]
  if vtype=="uri" and type(v)=="string" then v = v:gsub("^tel:",""):gsub("^mailto:","") end
  if type(v)=="table" then return table.concat(v, " ") end
  return v
end

local function extract_entity(ent)
  local name,email,url,phone = "","","",""
  local kind, address = "", ""
  if ent.vcardArray and ent.vcardArray[1]=="vcard" and ent.vcardArray[2] then
    for _, it in ipairs(ent.vcardArray[2]) do
      local prop, val = it[1], pick_jcard(it)
      if prop=="fn" or prop=="org" then name = val or name end
      if prop=="email" then email = val or email end
      if prop=="tel" then phone = val or phone end
      if prop=="url" then url = val or url end
      if prop=="kind" then kind = val or kind end
      if prop=="adr" then
        local meta = type(it[2])=="table" and it[2] or {}
        local label = meta.label
        if type(label)=="string" and #label>0 then
          address = label:gsub("\\r\\n","\\n"):gsub("\\n"," ")
        elseif type(val)=="string" and #val>0 then
          address = val
        end
      end
    end
  end
  if (url=="" or not url) and ent.links then
    for _, l in ipairs(ent.links) do
      if l.rel=="about" or l.type=="text/html" then url=l.href break end
    end
  end
  return name or "", email or "", url or "", phone or "", kind or "", address or ""
end

local function render_links(links, indent)
  if not links or #links==0 then return end
  section("Links", indent)
  for _, l in ipairs(links) do
    local rel = l.rel and ("["..l.rel.."] ") or ""
    local href = l.href or ""
    local typ = l.type and (" ("..l.type..")") or ""
    out(string.rep("  ", indent+1) .. "- " .. rel .. href .. typ)
  end
end

local function render_notices(kind, arr, indent)
  if not arr or #arr==0 then return end
  section(L(kind), indent)
  for _, n in ipairs(arr) do
    if n.title then out(string.rep("  ", indent+1) .. "* " .. n.title) end
    if n.description and #n.description>0 then
      for _, line in ipairs(n.description) do
        out(string.rep("  ", indent+1) .. "  - " .. S(line))
      end
    end
    if n.links and #n.links>0 then
      for _, l in ipairs(n.links) do
        local rel = l.rel and ("["..l.rel.."] ") or ""
        local href = l.href or ""
        local typ = l.type and (" ("..l.type..")") or ""
        out(string.rep("  ", indent+1) .. "  - Link: " .. rel .. href .. typ)
      end
    end
  end
end

local function render_events(events, indent)
  if not events or #events==0 then return end
  section("Events", indent)
  for _, e in ipairs(events) do
    out(string.rep("  ", indent+1) .. string.format("%s: %s", nice_event(e.eventAction), S(e.eventDate)))
  end
end

local function render_status(status, indent)
  if not status or #status==0 then return end
  section("Status", indent)
  out(string.rep("  ", indent+1) .. table.concat(status, ", "))
end

local function render_variants(variants, indent)
  if not variants or #variants==0 then return end
  section("Variants", indent)
  for _, v in ipairs(variants) do
    local relation = v.relation and table.concat(v.relation, ", ") or "relation"
    out(string.rep("  ", indent+1) .. "- Relation: " .. relation)
    if v.variantNames and #v.variantNames>0 then
      local names={}
      for _, vn in ipairs(v.variantNames) do names[#names+1] = vn.ldhName or vn.unicodeName or "?" end
      out(string.rep("  ", indent+2) .. "Names: " .. table.concat(names, ", "))
    end
  end
end

local function render_secure_dns(sd, indent)
  if not sd then return end
  y_emit("DNSSEC", (sd.delegationSigned and "Enabled" or "Disabled"), indent)
  if sd.dsData and #sd.dsData>0 then
    section("DS Records", indent)
    for _, ds in ipairs(sd.dsData) do
      out(string.rep("  ", indent+1) .. string.format("- keyTag=%s; algorithm=%s; digestType=%s; digest=%s",
          S(ds.keyTag), S(ds.algorithm), S(ds.digestType), S(ds.digest)))
    end
  end
  if sd.keyData and #sd.keyData>0 then
    section("Key Data", indent)
    for _, kd in ipairs(sd.keyData) do
      out(string.rep("  ", indent+1) .. string.format("- flags=%s; protocol=%s; algorithm=%s; publicKey=%s",
          S(kd.flags), S(kd.protocol), S(kd.algorithm), S(kd.publicKey)))
    end
  end
end

local function render_nameservers(nss, indent)
  if not nss or #nss==0 then return end
  section("Name Servers", indent)
  for _, ns in ipairs(nss) do
    local name = ns.ldhName or ns.unicodeName or "?"
    out(string.rep("  ", indent+1) .. "- " .. name)
    if ns.ipAddresses then
      local v4 = ns.ipAddresses.v4 or {}
      local v6 = ns.ipAddresses.v6 or {}
      if #v4>0 then out(string.rep("  ", indent+2) .. "IPv4: " .. table.concat(v4, ", ")) end
      if #v6>0 then out(string.rep("  ", indent+2) .. "IPv6: " .. table.concat(v6, ", ")) end
    end
  end
end

local function render_entity_events(events, indent)
  if not events or #events==0 then return end
  out(string.rep("  ", indent) .. "Events:")
  for _, e in ipairs(events) do
    out(string.rep("  ", indent+1) .. string.format("%s: %s", nice_event(e.eventAction), S(e.eventDate)))
  end
end

local function render_entities(entities, visited, indent)
  if not entities or #entities==0 then return end
  visited = visited or {}
  section("Entities", indent)
  local function _render(list)
    for _, ent in ipairs(list) do
      local h = ent.handle or (ent.vcardArray and ent.vcardArray[2] and "vcard") or tostring(ent)
      if not (h and visited[h]) then
        if h then visited[h] = true end
        local name,email,url,phone,kind,address = extract_entity(ent)
        local roles = ent.roles and table.concat(ent.roles, ", ") or ""
        local line = (name~="" and name or (ent.handle or "Entity")) .. (roles~="" and (" ["..roles.."]") or "")
        out(string.rep("  ", indent+1) .. "- " .. line)
        if kind~="" then out(string.rep("  ", indent+2) .. "Kind: " .. kind) end
        if address~="" then out(string.rep("  ", indent+2) .. "Address: " .. address) end
        if email~="" then out(string.rep("  ", indent+2) .. "Email: " .. email) end
        if phone~="" then out(string.rep("  ", indent+2) .. "Phone: " .. phone) end
        if url~="" then out(string.rep("  ", indent+2) .. "URL: " .. url) end
        if ent.publicIds and #ent.publicIds>0 then
          for _, id in ipairs(ent.publicIds) do
            out(string.rep("  ", indent+2) .. string.format("PublicId: %s = %s", S(id.type), S(id.identifier)))
          end
        end
        if ent.remarks and #ent.remarks>0 then
          for _, r in ipairs(ent.remarks) do
            local rtitle = r.title or "remarks"
            out(string.rep("  ", indent+2) .. "Remarks ("..rtitle.."):")
            if r.description and #r.description>0 then
              for _, line in ipairs(r.description) do out(string.rep("  ", indent+3) .. "- " .. S(line)) end
            end
          end
        end
        if ent.events and #ent.events>0 then render_entity_events(ent.events, indent+2) end
        if ent.links and #ent.links>0 then
          out(string.rep("  ", indent+2) .. "Links:")
          for _, l in ipairs(ent.links) do
            local rel = l.rel and ("["..l.rel.."] ") or ""
            local href = l.href or ""
            local typ = l.type and (" ("..l.type..")") or ""
            out(string.rep("  ", indent+3) .. "- " .. rel .. href .. typ)
          end
        end
      end
      if ent.entities and #ent.entities>0 then _render(ent.entities) end
    end
  end
  _render(entities)
end

local CLASS_FIELDS = {
  ["domain"] = function(o)
    render_nameservers(o.nameservers, 1); render_secure_dns(o.secureDNS, 1); render_variants(o.variants, 1)
  end,
  ["nameserver"] = function(o) render_nameservers({ o }, 1) end,
  ["ip network"] = function(o)
    y_emit("IP Range Start", o.startAddress, 1); y_emit("IP Range End", o.endAddress, 1)
    y_emit("IP Version", o.ipVersion, 1); y_emit("Network Name", o.name, 1); y_emit("Network Type", o.type, 1); y_emit("Parent Handle", o.parentHandle, 1)
  end,
  ["autnum"] = function(o)
    y_emit("ASN Range Start", o.startAutnum, 1); y_emit("ASN Range End", o.endAutnum, 1); y_emit("Name", o.name, 1)
  end,
}

local function render_cidr0(cidr0, indent)
  if not cidr0 or #cidr0==0 then return end
  section("CIDR", indent)
  for _, c in ipairs(cidr0) do
    local p = c.v4prefix or c.v6prefix or "prefix"
    local l = c.length or "?"
    out(string.rep("  ", indent+1) .. string.format("- %s/%s", S(p), S(l)))
  end
end

local function collect_registrar_abuse(entities)
  local registrar_name, registrar_id, registrar_url = "","",""
  local abuse_email, abuse_phone = "",""
  local function collect(list)
    if not list or #list==0 then return end
    for _, ent in ipairs(list) do
      local roles = ent.roles or {}
      local role_str = table.concat(roles, ",")
      if role_str:find("registrar") then
        registrar_name, _, registrar_url = extract_entity(ent)
        if ent.publicIds then
          for _, id in ipairs(ent.publicIds) do
            if id.type == "IANA Registrar ID" then registrar_id = id.identifier end
          end
        end
      end
      if role_str:find("abuse") then
        _, abuse_email, _, abuse_phone = extract_entity(ent)
      end
      if ent.entities and #ent.entities>0 then collect(ent.entities) end
    end
  end
  collect(entities)
  return registrar_name, registrar_id, registrar_url, abuse_email, abuse_phone
end

local function render_rdap(obj)
  local oc = obj.objectClassName or "object"
  section(string.upper(oc), 0)
  if obj.ldhName or obj.unicodeName then
    out("  Primary Name: " .. (obj.unicodeName or obj.ldhName))
  end
  y_emit("Handle", obj.handle, 1)
  y_emit("Object Class", oc, 1)
  y_emit("Country", obj.country, 1)
  y_emit("WHOIS (Port43)", obj.port43, 1)

  local f = CLASS_FIELDS[oc]
            or CLASS_FIELDS[(qtype=="nameserver" and "nameserver")
            or (qtype=="asn" and "autnum")
            or ((qtype=="ipv4" or qtype=="ipv6") and "ip network")
            or oc]
  if f then f(obj) end

  local registrar_name, registrar_id, registrar_url, abuse_email, abuse_phone = collect_registrar_abuse(obj.entities)
  if (registrar_name~="" or abuse_email~="" or abuse_phone~="") then
    section("Registrar & Abuse", 0)
    if registrar_name~="" then
      out("  Registrar: " .. registrar_name)
      if registrar_id~="" then out("  Registrar IANA ID: " .. registrar_id) end
      if registrar_url~="" then out("  Registrar URL: " .. registrar_url) end
    end
    if abuse_email~="" then out("  Abuse Email: " .. abuse_email) end
    if abuse_phone~="" then out("  Abuse Phone: " .. abuse_phone) end
  end

  render_status(obj.status, 0)
  render_events(obj.events, 0)

  if obj.entities and #obj.entities>0 then render_entities(obj.entities, {}, 0) end
  if obj.cidr0_cidrs and #obj.cidr0_cidrs>0 then render_cidr0(obj.cidr0_cidrs, 0) end

  y_list("RDAP Conformance", obj.rdapConformance, 0)
  y_emit("Language", obj.lang, 0)
  render_links(obj.links, 0)
  render_notices("remarks", obj.remarks, 0)
  render_notices("notices", obj.notices, 0)
end

-- 6) Main
local rdap_obj, src, json_url = query_rdap(qtype, target)

local whois_raw, source
if rdap_obj then
  source = src
else
  whois_raw, source = whois_fallback_with_referral(qtype, target)
end

-- ==== format handling ====
local fmt = (args.format or args.arg_format or "yaml"):lower()
if fmt == "text" then fmt = "yaml" end  -- alias

local cleaned = whois_raw and clean_whois(whois_raw) or nil

local payload_json = {
  queryType = string.upper(qtype),
  query = query,
  target = target,
  source = source,
  rdapUrl = json_url,
  rdap = rdap_obj or cjson.null,
  whois = cleaned or cjson.null
}

if fmt == "json" then
  ngx.header["Content-Type"] = "application/json; charset=utf-8"
  ngx.say(cjson.encode(payload_json))
  return

else
  -- YAML pretty text (default)
  ngx.header["Content-Type"] = "text/plain; charset=utf-8"

  -- Meta section
  section("Result", 0)
  out("  Query Type: " .. string.upper(qtype))
  out("  Query: " .. query)
  out("  Target: " .. target)
  out("  Source: " .. source)
  if json_url then out("  RDAP JSON: " .. json_url) end

  out("")

  if rdap_obj then
    render_rdap(rdap_obj)
  else
    section("RDAP Not Available – Using WHOIS Fallback", 0)
    out("")
  end

  if cleaned then
    section("Traditional WHOIS (cleaned)", 0)
    local lines = {}
    for line in cleaned:gmatch("[^\r\n]+") do lines[#lines+1] = line end
    for _, l in ipairs(lines) do
      out("  - " .. l)
    end
  end

  ngx.say(table.concat(buf, "\n"))

  if fmt == "both" then
    ngx.say("")
    ngx.say("```json")
    ngx.say(cjson.encode(payload_json))
    ngx.say("```")
  end
end