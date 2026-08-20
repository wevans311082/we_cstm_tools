local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Fetches /robots.txt and lists Disallow paths that often hide admin,
backup, or API surfaces.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local INTERESTING = {"admin", "backup", "api", "login", "wp-", "console", "manager", "secret", ".git", "internal"}

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/robots.txt", {timeout = 5000, redirect_ok = false})
  if not resp or not resp.status or resp.status >= 400 or not resp.body then
    out.robots = "missing"
    return out
  end
  out.robots = "present"
  local paths = {}
  local interesting = {}
  for line in string.gmatch(resp.body, "[^\r\n]+") do
    local path = string.match(line, "^[Dd]isallow:%s*(%S+)")
    if path and path ~= "/" then
      table.insert(paths, path)
      local lower = string.lower(path)
      for _, token in ipairs(INTERESTING) do
        if string.find(lower, token, 1, true) then
          table.insert(interesting, path)
          break
        end
      end
    end
  end
  out.disallow = table.concat(paths, ",")
  out.interesting = table.concat(interesting, ",")
  return out
end
