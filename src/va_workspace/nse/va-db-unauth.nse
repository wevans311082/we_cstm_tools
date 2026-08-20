local comm = require "comm"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Unauthenticated probes for Redis, Memcached, and Elasticsearch HTTP.
Does not dump data; looks for INFO/stats/cluster name.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(
  {6379, 11211, 9200, 9300},
  {"redis", "memcached", "http", "https", "wap-wsp"}
)

action = function(host, port)
  local out = stdnse.output_table()
  if port.number == 6379 then
    local status, data = comm.exchange(host, port, "INFO\r\n", {timeout = 4000, bytes = 2048})
    if status and data and string.find(data, "redis_version") then
      out.service = "redis"
      out.unauth = "yes"
      out.detail = string.match(data, "redis_version:[^\r\n]+") or "INFO ok"
    else
      out.service = "redis"
      out.unauth = "no"
    end
    return out
  end
  if port.number == 11211 then
    local status, data = comm.exchange(host, port, "stats\r\n", {timeout = 4000, bytes = 2048})
    if status and data and string.find(string.lower(data), "stat") then
      out.service = "memcached"
      out.unauth = "yes"
    else
      out.service = "memcached"
      out.unauth = "no"
    end
    return out
  end
  -- Elasticsearch-ish HTTP
  local resp = http.get(host, port, "/", {timeout = 5000})
  if resp and resp.body and string.find(resp.body, "cluster_name") then
    out.service = "elasticsearch"
    out.unauth = "yes"
    out.detail = string.sub(resp.body, 1, 300)
  elseif resp and resp.status then
    out.service = "http"
    out.unauth = "unknown"
    out.status = tostring(resp.status)
  end
  return out
end
