local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Rsync daemon module list (@RSYNCD). Unauthenticated listing is a common
backup/artefact leak.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(873, "rsync")

action = function(host, port)
  local out = stdnse.output_table()
  local status, data = comm.exchange(host, port, "@RSYNCD: 29.0\n\n", {timeout = 5000, bytes = 2048})
  if not status then
    out.error = tostring(data)
    return out
  end
  out.banner = string.sub(data or "", 1, 200)
  if string.find(data or "", "@RSYNCD") or string.find(data or "", "\n") then
    out.modules = string.gsub(data, "[\r]", "")
    out.listed = "yes"
  else
    out.listed = "no"
  end
  return out
end
