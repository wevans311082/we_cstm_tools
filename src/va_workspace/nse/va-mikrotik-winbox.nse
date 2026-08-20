local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
MikroTik WinBox (8291) exposure. Port open is the finding; version via
stock mikrotik-routeros-version when available.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(8291, {"winbox", "unknown"})

action = function(host, port)
  local out = stdnse.output_table()
  out.winbox = "open"
  return out
end
