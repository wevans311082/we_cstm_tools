local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
IPMI 2.0 cipher-zero (no auth) check using the ipmi library when present.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(623, "asf-rmcp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out.ipmi = "open"
  local ok, ipmi = pcall(require, "ipmi")
  if not ok then
    return out
  end
  local status, info = pcall(function()
    return ipmi.Helper and ipmi.Helper:new(host, port)
  end)
  if status and info then
    out.library = "yes"
  end
  return out
end
