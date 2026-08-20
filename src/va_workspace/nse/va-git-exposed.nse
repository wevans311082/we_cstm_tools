local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Looks for common unauthenticated exposure paths on HTTP: Git metadata,
dotenv, phpinfo, Tomcat/manager, Spring actuator, server-status.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local PATHS = {
  {path = "/.git/HEAD", needle = "ref:"},
  {path = "/.env", needle = "="},
  {path = "/server-status", needle = "Apache"},
  {path = "/phpinfo.php", needle = "phpinfo"},
  {path = "/actuator/health", needle = "status"},
  {path = "/manager/html", needle = "Tomcat"},
  {path = "/console", needle = "WebLogic"},
  {path = "/.svn/entries", needle = ""},
}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  for _, item in ipairs(PATHS) do
    local resp = http.get(host, port, item.path, {timeout = 5000, redirect_ok = false})
    if resp and resp.status and resp.status < 400 and resp.body then
      if item.needle == "" or string.find(string.lower(resp.body), string.lower(item.needle), 1, true) then
        table.insert(hits, item.path .. ":" .. tostring(resp.status))
      end
    end
  end
  if #hits == 0 then
    out.exposed = "none"
  else
    out.exposed = table.concat(hits, ",")
  end
  return out
end
