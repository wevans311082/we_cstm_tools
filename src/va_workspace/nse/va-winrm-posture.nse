local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
WinRM HTTP(S) unauth snapshot: NTLM/Negotiate challenge and server headers
on 5985/5986. Does not authenticate.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({5985, 5986}, {"wsman", "http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  out.exposed = "yes"
  local path = "/wsman"
  local resp = http.get(host, port, path, {
    timeout = 6000,
    header = {Authorization = "Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="},
  })
  if not resp then
    out.http = "no-response"
    return out
  end
  out.status = tostring(resp.status or "")
  local www = (resp.header and (resp.header["www-authenticate"] or "")) or ""
  out.www_authenticate = www
  if string.find(string.lower(www), "ntlm") then
    out.ntlm = "yes"
  else
    out.ntlm = "no"
  end
  return out
end
