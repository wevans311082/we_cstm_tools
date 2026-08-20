local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
vSphere / ESXi / vCenter web UI and SDK paths.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local PATHS = {"/ui/", "/vsphere-client/", "/sdk", "/folder", "/cgi-bin/vmware/"}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  for _, path in ipairs(PATHS) do
    local resp = http.get(host, port, path, {timeout = 4000, redirect_ok = false})
    if resp and resp.status and resp.status ~= 404 then
      local body = string.lower(resp.body or "")
      if resp.status < 400 or string.find(body, "vmware") or string.find(body, "vsphere") then
        table.insert(hits, path .. ":" .. tostring(resp.status))
      end
    end
  end
  out.hits = table.concat(hits, ",")
  out.vsphere = (#hits > 0) and "yes" or "no"
  return out
end
