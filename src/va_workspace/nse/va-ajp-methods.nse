local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Apache JServ Protocol (8009) OPTIONS via the ajp library when available.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(8009, "ajp13")

action = function(host, port)
  local out = stdnse.output_table()
  out.ajp = "open"
  local ok, ajp = pcall(require, "ajp")
  if ok and ajp and ajp.Helper then
    local helper = ajp.Helper:new(host, port)
    local status = helper:connect()
    if status then
      local s2, response = helper:options("/")
      if s2 and response then
        out.options = tostring(response.status or "ok")
      end
      helper:close()
    end
  end
  return out
end
