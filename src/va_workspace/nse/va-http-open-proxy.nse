local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
HTTP CONNECT to example.com:443. Status 200 means an open proxy.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({80, 8080, 3128, 8000, 8888}, {"http", "http-proxy"})

action = function(host, port)
  local out = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local ok = socket:connect(host, port)
  if not ok then
    out.open_proxy = "no"
    return out
  end
  socket:send("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
  local status, data = socket:receive_lines(1)
  socket:close()
  if status and data and string.match(data, "200") then
    out.open_proxy = "yes"
  else
    out.open_proxy = "no"
  end
  return out
end
