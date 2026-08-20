local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
MQTT CONNECT with empty client id / no user. CONNACK return code 0 means
unauthenticated broker.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service({1883, 8883}, "mqtt")

action = function(host, port)
  local out = stdnse.output_table()
  -- MQTT 3.1.1 CONNECT, client-id "va", clean session, keepalive 0
  local pkt = stdnse.fromhex("101000044d5154540402000000027661")
  local status, data = comm.exchange(host, port, pkt, {timeout = 4000, bytes = 8})
  if status and data and #data >= 4 then
    -- CONNACK is 0x20, remaining length, flags, return code
    local rc = data:byte(4)
    out.connack = tostring(rc)
    if rc == 0 then
      out.unauth = "yes"
    else
      out.unauth = "no"
    end
  else
    out.unauth = "unknown"
  end
  return out
end
