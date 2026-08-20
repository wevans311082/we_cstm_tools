local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Telnet banner capture. Flags login prompts and lack of encryption —
still common on printers, cameras, and ICS.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(23, "telnet")

action = function(host, port)
  local out = stdnse.output_table()
  local status, data = comm.exchange(host, port, "\r\n", {timeout = 4000, bytes = 512, recv_before = true})
  if not status then
    out.error = tostring(data)
    return out
  end
  out.banner = string.sub(string.gsub(data or "", "[%c]", " "), 1, 300)
  out.cleartext = "yes"
  local lower = string.lower(out.banner)
  if string.find(lower, "login") or string.find(lower, "username") or string.find(lower, "password") then
    out.login_prompt = "yes"
  else
    out.login_prompt = "no"
  end
  return out
end
