local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
X11 open TCP (6000+). An unauthenticated X server is full session control.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({6000, 6001, 6002}, "x11")

action = function(host, port)
  local out = stdnse.output_table()
  -- X11 setup packet is binary; a completed TCP connect is already evidence.
  local status, err = comm.exchange(host, port, "", {timeout = 3000, bytes = 8, recv_before = true})
  out.x11 = "open"
  if status then
    out.banner_hex = stdnse.tohex(err or ""):sub(1, 32)
  end
  return out
end
