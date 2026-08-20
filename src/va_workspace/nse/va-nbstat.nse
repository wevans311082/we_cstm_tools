local stdnse = require "stdnse"
local table = require "table"

description = [[
NetBIOS name table (nbstat) via the netbios library. Hostnames and
<20> workstation names help inventory Windows estates.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

hostrule = function(host)
  return true
end

action = function(host)
  local out = stdnse.output_table()
  local ok, netbios = pcall(require, "netbios")
  if not ok then
    out.error = "netbios library missing"
    return out
  end
  local status, names = netbios.get_names(host)
  if status and type(names) == "table" then
    local list = {}
    for _, n in ipairs(names) do
      table.insert(list, tostring(n.name or n))
    end
    out.names = table.concat(list, ",")
  else
    out.names = ""
    out.detail = tostring(names or "")
  end
  return out
end
