local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Flags default/vendor HTTP pages (IIS, Apache, nginx, Tomcat, Fortinet,
Citrix, vSphere) which often indicate an unhardened management interface.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local SIGNATURES = {
  {"IIS Windows Server", "iis-default"},
  {"Apache2 Debian Default", "apache-debian-default"},
  {"Welcome to nginx", "nginx-default"},
  {"Tomcat", "tomcat"},
  {"It works!", "apache-itworks"},
  {"Microsoft Internet Information Services", "iis-welcome"},
  {"vSphere", "vsphere"},
  {"Citrix Gateway", "citrix-gateway"},
  {"FortiGate", "fortigate"},
  {"pfSense", "pfsense"},
  {"UniFi", "unifi"},
  {"Proxmox", "proxmox"},
}

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 8000})
  if not resp or not resp.body then
    out.default_page = "unknown"
    return out
  end
  local body = resp.body
  local hits = {}
  for _, sig in ipairs(SIGNATURES) do
    if string.find(body, sig[1], 1, true) then
      table.insert(hits, sig[2])
    end
  end
  if #hits == 0 then
    out.default_page = "no"
  else
    out.default_page = "yes"
    out.product = table.concat(hits, ",")
  end
  return out
end
