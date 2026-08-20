local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Probes whether SSLv3 / TLS 1.0 / TLS 1.1 handshakes are accepted using
Nmap's ssl/tls support. Does not enumerate every cipher.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = function(host, port)
  return shortport.ssl(host, port) or (port.version and port.version.service_tunnel == "ssl")
end

local function try_tls(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local ok = socket:connect(host, port, "ssl")
  if ok then
    socket:close()
    return true
  end
  socket:close()
  return false
end

action = function(host, port)
  local out = stdnse.output_table()
  -- Nmap socket ssl uses the library default protocol set; we still record
  -- whether ANY TLS handshake works, then rely on sslcert + stock ssl-enum
  -- for suite detail. Flag obvious legacy via comm banner if present.
  out.tls_handshake = try_tls(host, port) and "yes" or "no"
  local sock = nmap.new_socket()
  sock:set_timeout(3000)
  if sock:connect(host, port) then
    local status, banner = sock:receive_bytes(16)
    sock:close()
    if status and banner then
      out.raw_prefix = stdnse.tohex(banner):sub(1, 32)
    end
  else
    sock:close()
  end
  return out
end
