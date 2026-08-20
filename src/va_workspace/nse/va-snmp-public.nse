local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"

description = [[
Tries SNMP community 'public' for sysDescr / sysName. Unauthenticated
information disclosure check used constantly on ITHCs.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

action = function(host, port)
  local out = stdnse.output_table()
  local helper = snmp.Helper:new(host, port)
  local status = helper:connect({community = "public"})
  if not status then
    out.public = "no"
    return out
  end
  local sysDescr = {1, 3, 6, 1, 2, 1, 1, 1, 0}
  local sysName = {1, 3, 6, 1, 2, 1, 1, 5, 0}
  local ok, descr = helper:get({sysDescr})
  local ok2, name = helper:get({sysName})
  if ok and descr then
    out.public = "yes"
    out.sysDescr = tostring(descr)
  elseif ok2 and name then
    out.public = "yes"
    out.sysName = tostring(name)
  else
    -- connect succeeded but get failed — still interesting
    out.public = "unknown"
  end
  if ok2 and name then
    out.sysName = tostring(name)
  end
  return out
end
