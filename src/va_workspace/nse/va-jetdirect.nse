local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
HP JetDirect / raw print (9100). Open means unauth print / PJL.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({9100, 515, 631}, {"jetdirect", "printer", "ipp"})

action = function(host, port)
  local out = stdnse.output_table()
  out.printing = "open"
  if port.number == 9100 then
    out.jetdirect = "yes"
  end
  return out
end
