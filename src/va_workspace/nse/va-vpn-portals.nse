local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Unauth HTTP(S) fingerprints for FortiGate, GlobalProtect, Pulse/Ivanti,
Cisco ASA, Citrix Gateway, and RD Web Access.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local PATHS = {
  {"/remote/login", "fortigate"},
  {"/global-protect/login.esp", "globalprotect"},
  {"/dana-na/auth/url_default/welcome.cgi", "pulse"},
  {"/+CSCOE+/logon.html", "cisco-asa"},
  {"/logon/LogonPoint/index.html", "citrix"},
  {"/RDWeb/Pages/en-US/login.aspx", "rdweb"},
}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  local products = {}
  for _, item in ipairs(PATHS) do
    local resp = http.get(host, port, item[1], {timeout = 4000, redirect_ok = false})
    if resp and resp.status and resp.status ~= 404 and resp.status ~= 0 then
      table.insert(hits, item[1] .. ":" .. tostring(resp.status))
      table.insert(products, item[2])
    end
  end
  out.hits = table.concat(hits, ",")
  out.products = table.concat(products, ",")
  out.portal = (#hits > 0) and "yes" or "no"
  return out
end
