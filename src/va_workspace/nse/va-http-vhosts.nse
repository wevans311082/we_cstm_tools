local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Sends a small Host-header set (www, mail, vpn, nva, autodiscover, localhost)
and reports titles that differ from the IP virtual host.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local function title_of(body)
  if not body then return "" end
  return string.match(body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)") or ""
end

action = function(host, port)
  local out = stdnse.output_table()
  local base = http.get(host, port, "/", {timeout = 5000})
  local base_title = title_of(base and base.body)
  out.default_title = base_title
  local names = {"www", "mail", "vpn", "remote", "nva", "autodiscover", "localhost", "admin"}
  if host.name then
    table.insert(names, 1, host.name)
  end
  local hits = {}
  for _, name in ipairs(names) do
    local resp = http.get(host, port, "/", {
      timeout = 4000,
      header = {Host = name},
    })
    local t = title_of(resp and resp.body)
    if t ~= "" and t ~= base_title then
      table.insert(hits, name .. "=" .. string.sub(t, 1, 60))
    end
  end
  if #hits == 0 then
    out.vhosts = "none"
  else
    out.vhosts = table.concat(hits, ",")
  end
  return out
end
