local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local url = require "url"

description = [[
Follows a single HTTP redirect and reports if Location points at a
different hostname — a scope-drift hint for CHECK testers.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 8000, redirect_ok = false})
  if not resp then
    out.error = "no response"
    return out
  end
  out.status = tostring(resp.status or "")
  local loc = resp.header and (resp.header.location or resp.header.Location) or ""
  out.location = loc
  if loc == "" then
    out.off_host = "no"
    return out
  end
  local parsed = url.parse(loc)
  local loc_host = parsed and parsed.host or ""
  local orig = host.targetname or host.name or host.ip
  if loc_host ~= "" and loc_host ~= orig and loc_host ~= host.ip then
    out.off_host = "yes"
    out.redirect_host = loc_host
  else
    out.off_host = "no"
  end
  return out
end
