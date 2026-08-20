local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts AXFR for the PTR/hostname zone. Success leaks the full zone.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  local zone = host.name or host.targetname or ""
  if zone == "" then
    out.axfr = "skipped-no-name"
    return out
  end
  -- parent zone: drop first label
  local parent = string.match(zone, "%.(.+)$") or zone
  out.zone = parent
  local status, result = dns.query(parent, {
    host = host.ip,
    port = port.number,
    proto = "tcp",
    dtype = "AXFR",
    retAll = true,
  })
  if status and result then
    out.axfr = "yes"
    if type(result) == "table" then
      out.records = tostring(#result)
    else
      out.records = tostring(result)
    end
  else
    out.axfr = "no"
  end
  return out
end
