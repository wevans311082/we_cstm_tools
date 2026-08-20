local ldap = require "ldap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Anonymous LDAP RootDSE: naming contexts, vendor, and function level if
the server answers an unauthenticated base search.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({389, 636, 3268, 3269}, {"ldap", "ldapssl"})

action = function(host, port)
  local out = stdnse.output_table()
  local ok, result = pcall(function()
    return ldap.search{
      host = host,
      port = port.number,
      dn = "",
      scope = ldap.SCOPE.BASE,
      filter = "(objectClass=*)",
      attributes = {
        "defaultNamingContext",
        "namingContexts",
        "dnsHostName",
        "ldapServiceName",
        "serverName",
        "domainFunctionality",
        "forestFunctionality",
        "vendorName",
      },
    }
  end)
  if not ok then
    -- older ldap.searchQuery style
    out.error = tostring(result)
    return out
  end
  if type(result) == "table" then
    for k, v in pairs(result) do
      if type(v) == "table" then
        out[tostring(k)] = table.concat(v, ",")
      else
        out[tostring(k)] = tostring(v)
      end
    end
  else
    out.raw = tostring(result or "")
  end
  if out.defaultNamingContext or out.namingContexts then
    out.anonymous = "yes"
  end
  return out
end
