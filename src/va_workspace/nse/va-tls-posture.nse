local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local os_date = os.date
local os_time = os.time

description = [[
Certificate posture for TLS listeners: CN, expiry, key bits, self-signed.
Focused CHECK evidence rather than a full cipher dump.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.service_tunnel == "ssl"
end

local function name_from(dn)
  if type(dn) ~= "table" then
    return tostring(dn or "")
  end
  return dn.commonName or dn.CN or stdnse.string_or_blank(tostring(dn))
end

action = function(host, port)
  local ok, cert = sslcert.getCertificate(host, port)
  local out = stdnse.output_table()
  if not ok or not cert then
    out.error = "no certificate"
    return out
  end
  out.subject = name_from(cert.subject)
  out.issuer = name_from(cert.issuer)
  if cert.pubkey then
    out.key_type = cert.pubkey.type or ""
    out.key_bits = tostring(cert.pubkey.bits or "")
  end
  local not_after = ""
  if cert.validity and cert.validity.notAfter then
    not_after = tostring(cert.validity.notAfter)
  end
  out.not_after = not_after
  if cert.subject and cert.issuer then
    out.self_signed = tostring(name_from(cert.subject) == name_from(cert.issuer))
  end
  local bits = tonumber(out.key_bits)
  if bits and bits > 0 and bits < 2048 then
    out.weak_key = "yes"
  else
    out.weak_key = "no"
  end
  -- expiry: if notAfter is a table with year/month/day from sslcert
  if type(cert.validity) == "table" and type(cert.validity.notAfter) == "table" then
    local t = cert.validity.notAfter
    local exp = os_time({
      year = t.year, month = t.month, day = t.day,
      hour = t.hour or 0, min = t.min or 0, sec = t.sec or 0,
    })
    if exp and exp < os_time() then
      out.expired = "yes"
    else
      out.expired = "no"
    end
  else
    out.expired = "unknown"
  end
  return out
end
