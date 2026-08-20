local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Sends an Origin: https://evil.example probe and reports wildcard or
reflecting CORS (Access-Control-Allow-Origin).
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {
    timeout = 8000,
    header = {Origin = "https://evil.example"},
  })
  if not resp or not resp.header then
    out.cors = "unknown"
    return out
  end
  local acao = resp.header["access-control-allow-origin"] or ""
  local acac = resp.header["access-control-allow-credentials"] or ""
  out.acao = acao
  out.credentials = acac
  if acao == "*" then
    out.cors = "wildcard"
  elseif string.find(acao, "evil.example", 1, true) then
    out.cors = "reflects-origin"
  elseif acao ~= "" then
    out.cors = "restricted"
  else
    out.cors = "none"
  end
  return out
end
