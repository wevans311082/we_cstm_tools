local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Kubernetes apiserver (6443) /version and /api anonymous access check.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({6443, 8443}, {"https", "ssl/http", "http"})

action = function(host, port)
  local out = stdnse.output_table()
  local ver = http.get(host, port, "/version", {timeout = 5000})
  if ver and ver.status == 200 and ver.body and string.find(ver.body, "gitVersion") then
    out.apiserver = "yes"
    out.anonymous_version = "yes"
    out.detail = string.sub(ver.body, 1, 200)
  else
    out.apiserver = "no"
    out.anonymous_version = "no"
  end
  local api = http.get(host, port, "/api", {timeout = 4000})
  if api and api.status == 200 then
    out.anonymous_api = "yes"
  else
    out.anonymous_api = "no"
  end
  return out
end
