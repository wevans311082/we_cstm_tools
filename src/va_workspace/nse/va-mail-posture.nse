local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
SMTP unauth snapshot: banner/EHLO capabilities, STARTTLS, and whether
VRFY/EXPN are advertised (user enum). Does not send relay probes that
could bounce mail.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({25, 587, 465}, {"smtp", "submission", "smtps"})

action = function(host, port)
  local out = stdnse.output_table()
  local socket, response = smtp.connect(host, port, {timeout = 8000, ssl = (port.number == 465)})
  if not socket then
    out.error = tostring(response)
    return out
  end
  out.banner = tostring(response or "")
  local status, ehlo = smtp.ehlo(socket, "va.workspace.invalid")
  smtp.quit(socket)
  if status and type(ehlo) == "table" then
    local caps = {}
    for _, line in ipairs(ehlo) do
      table.insert(caps, tostring(line))
    end
    local blob = string.upper(table.concat(caps, " "))
    out.capabilities = table.concat(caps, " | ")
    out.starttls = string.find(blob, "STARTTLS", 1, true) and "yes" or "no"
    out.vrfy = string.find(blob, "VRFY", 1, true) and "yes" or "no"
    out.expn = string.find(blob, "EXPN", 1, true) and "yes" or "no"
  elseif status then
    out.capabilities = tostring(ehlo)
  end
  return out
end
