local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
PROPFIND / OPTIONS check for WebDAV. Does not write files.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local opt = http.generic_request(host, port, "OPTIONS", "/", {timeout = 5000})
  local allow = ""
  local dav = ""
  if opt and opt.header then
    allow = opt.header.allow or opt.header.Allow or ""
    dav = opt.header.dav or opt.header.DAV or ""
  end
  out.allow = allow
  out.dav_header = dav
  local prop = http.generic_request(host, port, "PROPFIND", "/", {
    timeout = 5000,
    header = {Depth = "0", ["Content-Type"] = "text/xml"},
  })
  out.propfind_status = prop and tostring(prop.status or "") or ""
  local blob = string.upper(allow .. " " .. dav .. " " .. out.propfind_status)
  if string.find(blob, "DAV") or string.find(blob, "PROPFIND") or out.propfind_status == "207" then
    out.webdav = "yes"
  else
    out.webdav = "no"
  end
  return out
end
