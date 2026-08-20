local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
HP iLO / Dell iDRAC / SuperMicro BMC web UI fingerprints.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({443, 80, 8443, 5900}, {"https", "http"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 5000})
  local body = string.lower((resp and resp.body) or "")
  local product = "no"
  if string.find(body, "ilo") or string.find(body, "hewlett") then
    product = "ilo"
  elseif string.find(body, "idrac") or string.find(body, "dell") then
    product = "idrac"
  elseif string.find(body, "supermicro") or string.find(body, "atn") then
    product = "supermicro"
  end
  out.bmc = product
  return out
end
