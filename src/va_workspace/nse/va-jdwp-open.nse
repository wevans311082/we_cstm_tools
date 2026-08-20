local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Java Debug Wire Protocol handshake (JDWP-Handshake). An open JDWP port
is remote code execution on the JVM.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({8000, 5005, 8787, 9009}, {"jdwp", "tcpwrapped"})

action = function(host, port)
  local out = stdnse.output_table()
  local status, data = comm.exchange(host, port, "JDWP-Handshake", {timeout = 4000, bytes = 32})
  if status and data and string.find(data, "JDWP-Handshake", 1, true) then
    out.jdwp = "yes"
  else
    out.jdwp = "no"
  end
  return out
end
