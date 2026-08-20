local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Windows RPC endpoint mapper (135). Confirms the mapper answers; full
interface dump left to stock msrpc-enum when intensity allows.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(135, "msrpc")

action = function(host, port)
  local out = stdnse.output_table()
  out.endpoint_mapper = "open"
  local ok, msrpc = pcall(require, "msrpc")
  if ok and msrpc then
    out.msrpc_lib = "yes"
  end
  return out
end
