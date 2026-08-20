local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Elasticsearch unauth / and /_cat/indices.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({9200, 9300}, {"http", "wap-wsp"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 5000})
  if resp and resp.body and string.find(resp.body, "cluster_name") then
    out.elasticsearch = "yes"
    out.unauth = "yes"
    out.detail = string.sub(resp.body, 1, 250)
  else
    out.elasticsearch = "no"
    out.unauth = "no"
  end
  return out
end
