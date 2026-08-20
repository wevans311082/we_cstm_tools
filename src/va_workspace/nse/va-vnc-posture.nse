local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
RFB protocol version banner for VNC. Notes None-authentication if the
server advertises security type 1.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({5900, 5901, 5902}, "vnc")

action = function(host, port)
  local out = stdnse.output_table()
  local status, banner = comm.exchange(host, port, "", {timeout = 4000, bytes = 32, recv_before = true})
  if not status then
    out.error = tostring(banner)
    return out
  end
  out.banner = string.gsub(banner or "", "[\r\n]", "")
  if string.find(out.banner, "RFB") then
    out.vnc = "yes"
  end
  -- send RFB 003.008 and read security types
  local sock_ok, data = comm.exchange(host, port, "RFB 003.008\n", {timeout = 4000, bytes = 16})
  if sock_ok and data then
    out.security_blob = stdnse.tohex(data):sub(1, 32)
    -- security type None is 0x01
    if string.find(data, "\001", 1, true) then
      out.none_auth = "yes"
    else
      out.none_auth = "no"
    end
  end
  return out
end
