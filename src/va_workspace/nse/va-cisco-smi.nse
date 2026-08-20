local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Cisco Smart Install (TCP/4786). The port being open is itself a finding;
this script confirms a banner/handshake byte.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.portnumber(4786, "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out.smart_install = "open"
  local status, data = comm.exchange(host, port, "", {timeout = 3000, bytes = 32, recv_before = true})
  if status and data and #data > 0 then
    out.banner_hex = stdnse.tohex(data):sub(1, 40)
  end
  return out
end
