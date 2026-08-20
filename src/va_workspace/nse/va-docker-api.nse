local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Unauthenticated Docker Engine API on 2375 (/version, /info). Root-equivalent
on the host if it answers.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({2375, 2376}, {"docker", "http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/version", {timeout = 5000})
  if resp and resp.status == 200 and resp.body and string.find(resp.body, "ApiVersion") then
    out.docker = "yes"
    out.unauth = "yes"
    out.detail = string.sub(resp.body, 1, 400)
  else
    out.docker = "no"
    out.unauth = "no"
  end
  return out
end
