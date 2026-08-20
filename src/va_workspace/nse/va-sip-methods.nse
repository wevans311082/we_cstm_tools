local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
SIP OPTIONS ping. Records allowed methods and Server/User-Agent.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({5060, 5061}, {"sip", "sips"})

action = function(host, port)
  local out = stdnse.output_table()
  local ip = host.ip
  local req = table.concat({
    "OPTIONS sip:" .. ip .. " SIP/2.0",
    "Via: SIP/2.0/UDP nmap.va.invalid;branch=z9hG4bK-va",
    "From: <sip:va@nmap.va.invalid>;tag=va",
    "To: <sip:" .. ip .. ">",
    "Call-ID: va-" .. tostring(port.number) .. "@nmap.va.invalid",
    "CSeq: 1 OPTIONS",
    "Contact: <sip:va@nmap.va.invalid>",
    "Max-Forwards: 70",
    "Content-Length: 0",
    "",
    "",
  }, "\r\n")
  local proto = port.protocol == "tcp" and "tcp" or "udp"
  local status, data = comm.exchange(host, port, req, {timeout = 4000, bytes = 1500, proto = proto})
  if not status then
    out.error = tostring(data)
    return out
  end
  out.response = string.sub(data or "", 1, 400)
  out.server = string.match(data or "", "[Ss]erver:%s*([^\r\n]+)") or ""
  out.allow = string.match(data or "", "[Aa]llow:%s*([^\r\n]+)") or ""
  if string.find(data or "", "SIP/2.0") then
    out.sip = "yes"
  else
    out.sip = "no"
  end
  return out
end
