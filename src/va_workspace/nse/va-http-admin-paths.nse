local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks a short list of management paths (status 200/301/401/403).
Not a directory brute — CHECK-safe reconnaissance.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local PATHS = {
  "/admin", "/administrator", "/login", "/wp-login.php", "/wp-admin/",
  "/phpmyadmin/", "/manager/html", "/console", "/cgi-bin/",
  "/remote", "/vpn", "/owa", "/ecp", "/horizon",
}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  for _, path in ipairs(PATHS) do
    local resp = http.get(host, port, path, {timeout = 4000, redirect_ok = false})
    if resp and resp.status and (resp.status == 200 or resp.status == 401
        or resp.status == 403 or resp.status == 301 or resp.status == 302) then
      table.insert(hits, path .. ":" .. tostring(resp.status))
    end
  end
  out.hits = table.concat(hits, ",")
  if #hits == 0 then
    out.admin_paths = "none"
  else
    out.admin_paths = "yes"
  end
  return out
end
