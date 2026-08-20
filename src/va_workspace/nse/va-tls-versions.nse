local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Records whether a TLS handshake succeeds. Pair with the Python
va_workspace.tools.tls_versions probe for SSLv3/TLS1.0/1.1/1.2/1.3.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = function(host, port)
  return shortport.ssl(host, port) or (port.version and port.version.service_tunnel == "ssl")
end

action = function(host, port)
  local out = stdnse.output_table()
  local ok_tls, tls = pcall(require, "tls")
  local accepted = {}
  if ok_tls and tls and tls.PROTOCOLS then
    for name, _ in pairs(tls.PROTOCOLS) do
      table.insert(accepted, tostring(name))
    end
    out.tls_lib = "yes"
    out.protocols_known = table.concat(accepted, ",")
  else
    out.tls_lib = "no"
  end
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local ok = socket:connect(host, port, "ssl")
  socket:close()
  out.tls_handshake = ok and "yes" or "no"
  out.legacy_note = "use python tls_versions probe for per-version evidence"
  return out
end
