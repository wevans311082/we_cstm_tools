local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
NTP read-var / version via the ntp library when present; otherwise a
mode-6 version query through comm.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(123, "ntp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  local ok, ntp = pcall(require, "ntp")
  if ok and ntp then
    local helper = ntp.Helper:new(host, port)
    local status, info = helper:getInfo()
    if status and type(info) == "table" then
      out.version = tostring(info.version or info.ver or "")
      out.refid = tostring(info.refid or "")
      out.ntp = "yes"
      return out
    end
  end
  out.ntp = "open"
  return out
end
