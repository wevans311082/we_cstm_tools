local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Exchange / OWA / EWS / Autodiscover path check. 401/200 on these paths
identifies mail infrastructure for the attack surface note.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local PATHS = {
  "/owa/", "/ecp/", "/ews/", "/autodiscover/autodiscover.xml",
  "/Microsoft-Server-ActiveSync", "/rpc/rpcproxy.dll", "/oab/",
}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  for _, path in ipairs(PATHS) do
    local resp = http.get(host, port, path, {timeout = 4000, redirect_ok = false})
    if resp and resp.status and resp.status ~= 404 and resp.status ~= 400 then
      table.insert(hits, path .. ":" .. tostring(resp.status))
    end
  end
  out.hits = table.concat(hits, ",")
  out.exchange = (#hits > 0) and "yes" or "no"
  return out
end
