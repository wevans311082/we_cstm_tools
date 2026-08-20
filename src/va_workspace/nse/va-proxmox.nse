local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Proxmox VE manager (8006) fingerprint.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(8006, {"http", "https"})

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 5000})
  local body = string.lower((resp and resp.body) or "")
  if string.find(body, "proxmox") then
    out.proxmox = "yes"
  else
    out.proxmox = "no"
  end
  return out
end
