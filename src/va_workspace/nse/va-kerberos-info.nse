local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
TCP/UDP 88 Kerberos: records that a KDC is exposed. Does not spray users.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({88, 464}, {"kerberos-sec", "kpasswd", "kerberos"})

action = function(host, port)
  local out = stdnse.output_table()
  out.kdc = "open"
  out.protocol = port.protocol
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  local ok = sock:connect(host, port)
  if ok then
    out.connect = "yes"
    sock:close()
  else
    out.connect = "no"
  end
  return out
end
