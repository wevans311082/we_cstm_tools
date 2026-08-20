local ftp = require "ftp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tries anonymous FTP login and, if it works, lists the top-level directory.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth", "va"}

portrule = shortport.port_or_service(21, "ftp")

action = function(host, port)
  local out = stdnse.output_table()
  local socket, code, message, buffer = ftp.connect(host, port)
  if not socket then
    out.error = tostring(code or message or "connect failed")
    return out
  end
  local status, err = ftp.auth(socket, buffer, "anonymous", "va@workspace.invalid")
  if not status then
    out.anonymous = "denied"
    out.detail = tostring(err or "")
    ftp.close(socket)
    return out
  end
  out.anonymous = "allowed"
  local ok_list, list = pcall(ftp.list, socket, buffer, ".")
  ftp.close(socket)
  status = ok_list and list
  if status and type(list) == "table" then
    out.listing = table.concat(list, " | ")
  elseif status and type(list) == "string" then
    out.listing = string.sub(list, 1, 500)
  end
  return out
end
