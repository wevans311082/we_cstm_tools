local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"

description = [[
RDP listener posture: TLS certificate names if the service speaks TLS
(common with NLA). Hostname/domain in the cert is CHECK-useful evidence.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(3389, {"ms-wbt-server", "rdp"})

action = function(host, port)
  local out = stdnse.output_table()
  out.exposed = "yes"
  local ok, cert = pcall(sslcert.getCertificate, host, port)
  if ok and cert then
    out.tls = "yes"
    if cert.subject then
      out.subject = cert.subject.commonName or ""
    end
    if cert.issuer then
      out.issuer = cert.issuer.commonName or ""
    end
  else
    out.tls = "no-or-nla-plain"
  end
  return out
end
