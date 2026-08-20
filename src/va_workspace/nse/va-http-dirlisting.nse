local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects HTTP directory listing on / and /uploads/.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local listing = "no"
  for _, path in ipairs({"/", "/uploads/", "/files/", "/backup/"}) do
    local resp = http.get(host, port, path, {timeout = 4000})
    local body = string.lower((resp and resp.body) or "")
    if string.find(body, "index of") or string.find(body, "parent directory") then
      listing = "yes"
      out.path = path
      break
    end
  end
  out.dirlisting = listing
  return out
end
