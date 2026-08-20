local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Kibana (5601) status/login fingerprint.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(5601, {"http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/api/status", {timeout = 5000})
  local body = (resp and resp.body) or ""
  if string.find(string.lower(body), "kibana") or (resp and resp.status == 200 and string.find(body, "status")) then
    out.kibana = "yes"
  else
    local login = http.get(host, port, "/login", {timeout = 4000})
    out.kibana = (login and login.body and string.find(string.lower(login.body), "kibana")) and "yes" or "no"
  end
  return out
end
