local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
IMAP/POP3 unauth: banner, CAPABILITY, whether AUTH/LOGIN is offered
before STARTTLS (cleartext credential risk).
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({110, 143, 993, 995}, {"pop3", "imap", "pop3s", "imaps"})

action = function(host, port)
  local out = stdnse.output_table()
  local probe = "A1 CAPABILITY\r\n"
  if port.number == 110 or port.number == 995 then
    probe = "CAPA\r\n"
  end
  local status, data = comm.exchange(host, port, probe, {timeout = 5000, bytes = 800, recv_before = true})
  if not status then
    out.error = tostring(data)
    return out
  end
  out.banner = string.sub(data or "", 1, 250)
  local up = string.upper(data or "")
  out.starttls = string.find(up, "STARTTLS") and "yes" or "no"
  out.cleartext_auth = (string.find(up, "LOGIN") or string.find(up, "PLAIN") or string.find(up, "USER")) and "yes" or "no"
  return out
end
