local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Host-level role guess from open ports (DC, mail, database, web, jump).
Complements va's Python role inference with an NSE evidence line.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

hostrule = function(host)
  return true
end

local WATCH = {
  21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
  587, 623, 636, 993, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985,
  6379, 6443, 8443, 9200, 10250, 27017, 4786,
}

local function open_tcp(host, number)
  local p = nmap.get_port_state(host, {number = number, protocol = "tcp"})
  return p and p.state == "open"
end

action = function(host)
  local out = stdnse.output_table()
  local open = {}
  for _, n in ipairs(WATCH) do
    if open_tcp(host, n) then
      table.insert(open, tostring(n))
    end
  end
  out.open_watch = table.concat(open, ",")
  local function has(n)
    return open_tcp(host, n)
  end
  local role = "unknown"
  if has(445) and (has(88) or has(389)) then
    role = "domain-controller"
  elseif has(25) or has(587) then
    role = "mail"
  elseif has(1433) or has(3306) or has(5432) or has(27017) then
    role = "database"
  elseif has(2375) or has(6443) or has(10250) then
    role = "container-platform"
  elseif has(3389) then
    role = "jump-host"
  elseif has(80) or has(443) then
    role = "web"
  elseif has(22) then
    role = "unix-host"
  end
  out.role = role
  return out
end
