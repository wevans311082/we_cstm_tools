local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Looks for leftover backup/config files on the web root (web.config.bak,
wp-config.php.bak, .bak, .old, index.php~). Loud-ish; few requests.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery", "va"}

portrule = shortport.http

local PATHS = {
  "/web.config.bak", "/web.config.old", "/wp-config.php.bak",
  "/wp-config.php.old", "/config.php.bak", "/.env.bak",
  "/backup.zip", "/backup.sql", "/dump.sql", "/site.sql",
  "/index.php.bak", "/index.php~", "/web.config~",
}

action = function(host, port)
  local out = stdnse.output_table()
  local hits = {}
  for _, path in ipairs(PATHS) do
    local resp = http.head(host, port, path, {timeout = 4000, redirect_ok = false})
    if not resp or not resp.status then
      resp = http.get(host, port, path, {timeout = 4000, redirect_ok = false})
    end
    if resp and resp.status == 200 then
      table.insert(hits, path)
    end
  end
  out.backups = table.concat(hits, ",")
  out.found = (#hits > 0) and "yes" or "no"
  return out
end
