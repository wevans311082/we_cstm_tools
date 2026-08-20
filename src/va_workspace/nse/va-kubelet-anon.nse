local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Kubelet read-only / unauth ports (10250, 10255). Hitting /pods or
/runningpods without auth is a cluster compromise path.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({10250, 10255, 6443}, {"http", "https", "ssl/http"})

action = function(host, port)
  local out = stdnse.output_table()
  local paths = {"/pods", "/runningpods", "/metrics", "/healthz", "/version"}
  local hits = {}
  for _, path in ipairs(paths) do
    local resp = http.get(host, port, path, {timeout = 5000, redirect_ok = false})
    if resp and resp.status == 200 and resp.body then
      table.insert(hits, path)
    end
  end
  out.hits = table.concat(hits, ",")
  if #hits > 0 then
    out.kubelet = "yes"
    out.unauth = "yes"
  else
    out.kubelet = "no"
    out.unauth = "no"
  end
  return out
end
