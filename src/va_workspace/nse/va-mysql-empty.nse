local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
MySQL handshake: captures protocol version and whether the server allows
empty-password login for root (mysql library). Unauth only.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth", "va"}

portrule = shortport.port_or_service(3306, "mysql")

action = function(host, port)
  local out = stdnse.output_table()
  local ok, mysql = pcall(require, "mysql")
  if not ok then
    out.error = "mysql library missing"
    return out
  end
  local socket, response = mysql.connect(host, port, nil, {timeout = 5000})
  if not socket then
    out.error = tostring(response)
    return out
  end
  out.greeting = tostring(response or "")
  local status, err = mysql.login(socket, "root", "", {skipdb = true})
  if status then
    out.empty_root = "yes"
    mysql.close(socket)
  else
    out.empty_root = "no"
    out.detail = tostring(err or "")
    pcall(mysql.close, socket)
  end
  return out
end
