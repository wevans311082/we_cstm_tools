local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"

description = [[
Active Directory Web Services (9389). TLS cert names often leak the DC FQDN.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(9389, {"http", "https", "ssl/http"})

action = function(host, port)
  local out = stdnse.output_table()
  out.adws = "open"
  local ok, cert = pcall(sslcert.getCertificate, host, port)
  if ok and cert and cert.subject then
    out.subject = cert.subject.commonName or ""
  end
  return out
end
