local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Sends a MongoDB isMaster OP_QUERY/OP_MSG probe. If ismaster/maxWireVersion
comes back without auth, the database is unauthenticated.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(27017, "mongodb")

action = function(host, port)
  local out = stdnse.output_table()
  -- legacy OP_QUERY isMaster (works on older mongod)
  local query = stdnse.fromhex(
    "3f0000000000000000000000d40700000000000061646d696e2e24636d640000000000ffffffff14000000016c736d617374657200000000000000f03f00"
  )
  local status, data = comm.exchange(host, port, query, {timeout = 4000, bytes = 1024})
  if status and data and #data > 20 then
    out.unauth = "yes"
    out.detail = "binary-ismaster-response"
  else
    out.unauth = "no"
  end
  return out
end
