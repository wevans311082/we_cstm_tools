local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects WordPress (wp-login, wp-includes, generator tag) and notes
user-enum via ?author=1 if it redirects to /author/name.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local login = http.get(host, port, "/wp-login.php", {timeout = 5000, redirect_ok = false})
  local gen = http.get(host, port, "/", {timeout = 5000})
  local is_wp = (login and login.status and login.status < 400)
  if gen and gen.body and string.find(gen.body, "wp%-content") then
    is_wp = true
  end
  out.wordpress = is_wp and "yes" or "no"
  if is_wp then
    local author = http.get(host, port, "/?author=1", {timeout = 4000, redirect_ok = false})
    if author and author.status and author.status >= 300 and author.status < 400 then
      out.author_enum = author.header and (author.header.location or "") or "redirect"
    else
      out.author_enum = "no"
    end
  end
  return out
end
