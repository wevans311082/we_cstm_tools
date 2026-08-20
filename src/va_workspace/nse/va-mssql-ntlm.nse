local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
TDS pre-login / NTLM negotiate against MSSQL 1433 to recover version,
instance, and Windows domain without a password.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({1433, 1434}, {"ms-sql-s", "ms-sql-m"})

action = function(host, port)
  local out = stdnse.output_table()
  local ok, mssql = pcall(require, "mssql")
  if not ok then
    out.error = "mssql library missing"
    out.exposed = "yes"
    return out
  end
  local instance = mssql.Helper.InitInstance and mssql.Helper.InitInstance(host, port)
  if instance then
    out.exposed = "yes"
    local status, info = pcall(function()
      return instance:Connect()
    end)
    out.prelogin = status and "yes" or "no"
  else
    out.exposed = "yes"
  end
  return out
end
