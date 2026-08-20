local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Reads the SSH banner and KEXINIT name-lists. Flags legacy host keys,
ciphers, MACs, and kex (ssh-rsa, 3des, arcfour, group1, hmac-md5).
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.port_or_service(22, "ssh")

local function u32(buf, i)
  if i + 3 > #buf then
    return nil, i
  end
  local a, b, c, d = string.byte(buf, i, i + 3)
  return a * 16777216 + b * 65536 + c * 256 + d, i + 4
end

local function namelist(buf, i)
  local len
  len, i = u32(buf, i)
  if not len or i + len - 1 > #buf then
    return nil, i
  end
  local s = string.sub(buf, i, i + len - 1)
  return s, i + len
end

local WEAK = {
  "ssh-rsa", "ssh-dss", "3des-cbc", "arcfour", "arcfour128", "arcfour256",
  "hmac-md5", "hmac-md5-96", "diffie-hellman-group1-sha1",
  "diffie-hellman-group-exchange-sha1",
}

local function weak_hits(list)
  if not list then
    return ""
  end
  local found = {}
  local lower = string.lower(list)
  for _, alg in ipairs(WEAK) do
    if string.find(lower, alg, 1, true) then
      table.insert(found, alg)
    end
  end
  return table.concat(found, ",")
end

action = function(host, port)
  local out = stdnse.output_table()
  local socket = nmap.new_socket()
  socket:set_timeout(5000)
  local status, err = socket:connect(host, port)
  if not status then
    out.error = err
    return out
  end
  local banner
  status, banner = socket:receive_lines(1)
  if not status then
    socket:close()
    out.error = banner
    return out
  end
  banner = string.gsub(banner, "[\r\n]", "")
  out.banner = banner
  socket:send("SSH-2.0-va-workspace\r\n")
  local pkt
  status, pkt = socket:receive_bytes(4096)
  socket:close()
  if not status or not pkt or #pkt < 20 then
    out.kex = "unparsed"
    return out
  end
  -- skip record length (4) + padlen (1) + msg id should be 20 (KEXINIT)
  local i = 6
  local msg = string.byte(pkt, 5)
  -- some stacks put msg at byte 6 after padlen
  if msg ~= 20 then
    msg = string.byte(pkt, 6)
    i = 7
  end
  -- cookie 16 bytes
  i = i + 16
  local kex, hostkeys, enc_cs, enc_sc, mac_cs
  kex, i = namelist(pkt, i)
  hostkeys, i = namelist(pkt, i)
  enc_cs, i = namelist(pkt, i)
  enc_sc, i = namelist(pkt, i)
  mac_cs, i = namelist(pkt, i)
  out.kex = kex or ""
  out.host_keys = hostkeys or ""
  out.encryption = enc_cs or ""
  out.mac = mac_cs or ""
  local weak = {}
  for _, list in ipairs({kex, hostkeys, enc_cs, mac_cs}) do
    local hits = weak_hits(list)
    if hits ~= "" then
      table.insert(weak, hits)
    end
  end
  if #weak > 0 then
    out.weak_algorithms = table.concat(weak, ",")
  else
    out.weak_algorithms = ""
  end
  return out
end
