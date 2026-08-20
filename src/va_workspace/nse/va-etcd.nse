local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
etcd unauthenticated /version and /v2/keys.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({2379, 4001}, {"http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  local ver = http.get(host, port, "/version", {timeout = 4000})
  if ver and ver.status == 200 and ver.body and string.find(ver.body, "etcd") then
    out.etcd = "yes"
    out.unauth = "yes"
  else
    out.etcd = "no"
    out.unauth = "no"
  end
  return out
end
