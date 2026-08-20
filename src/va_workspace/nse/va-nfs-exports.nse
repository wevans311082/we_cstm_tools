local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Unauthenticated NFS export list via mountd (showmount -e equivalent).
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({111, 2049}, {"rpcbind", "nfs", "nfsd"})

action = function(host)
  local out = stdnse.output_table()
  local ok, mount = pcall(function()
    local m = rpc.Mount:new()
    m:Export(host)
    return m
  end)
  if not ok then
    out.error = tostring(mount)
    return out
  end
  -- rpc.Mount Export often fills m.export or returns via HighLevel
  local ok2, exports = pcall(function()
    local comm = rpc.Comm:new("rpcbind", 2)
    local mnt = rpc.Mount:new()
    local status, result = mnt:Export(host)
    return result
  end)
  if ok2 and type(exports) == "table" then
    local names = {}
    for _, item in ipairs(exports) do
      table.insert(names, tostring(item.name or item))
    end
    out.exports = table.concat(names, ",")
  elseif ok2 then
    out.exports = tostring(exports or "")
  else
    out.error = tostring(exports)
  end
  return out
end
