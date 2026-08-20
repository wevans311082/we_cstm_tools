local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
HashiCorp Consul HTTP API /v1/status/leader without ACL.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({8500, 8501}, {"http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/v1/status/leader", {timeout = 4000})
  if resp and resp.status == 200 then
    out.consul = "yes"
    out.unauth = "yes"
  else
    out.consul = "no"
    out.unauth = "no"
  end
  return out
end
