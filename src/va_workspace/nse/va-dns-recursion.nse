local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Asks the resolver for an external name with RD set. If it answers, it is
an open recursive resolver (amplification / cache-poisoning helper).
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

action = function(host, port)
  local out = stdnse.output_table()
  local status, result = dns.query("example.com", {
    host = host.ip,
    port = port.number,
    proto = port.protocol,
    dtype = "A",
    retAll = true,
  })
  if status and result then
    out.recursion = "yes"
    if type(result) == "table" then
      out.answers = table.concat(result, ",")
    else
      out.answers = tostring(result)
    end
  else
    out.recursion = "no"
    out.detail = tostring(result or "")
  end
  return out
end
