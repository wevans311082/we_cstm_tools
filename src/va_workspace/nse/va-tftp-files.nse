local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
TFTP RRQ for a short list of common names (cisco config, running-config,
pxelinux). Does not write.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(69, "tftp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  local ok, tftp = pcall(require, "tftp")
  out.tftp = "open"
  if not ok then
    return out
  end
  local files = {"running-config", "startup-config", "cisco.cfg", "network.cfg", "pxelinux.0"}
  local hits = {}
  for _, name in ipairs(files) do
    local status = pcall(function()
      return tftp.fetchFile and tftp.fetchFile(host, name)
    end)
    if status then
      table.insert(hits, name)
    end
  end
  out.readable = table.concat(hits, ",")
  return out
end
