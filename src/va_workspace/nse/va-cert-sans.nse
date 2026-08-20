local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Extracts DNS SANs (and CN) from TLS certificates so operators can spot
out-of-scope names and internal hostnames on internet-facing certs.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.service_tunnel == "ssl"
end

action = function(host, port)
  local ok, cert = sslcert.getCertificate(host, port)
  local out = stdnse.output_table()
  if not ok or not cert then
    out.error = "no certificate"
    return out
  end
  local names = {}
  if cert.subject and cert.subject.commonName then
    table.insert(names, cert.subject.commonName)
  end
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      local val = ext.value or ext.name
      if type(val) == "string" and (string.find(val, "DNS:") or string.find(val, "dnsName")) then
        for dns in string.gmatch(val, "DNS:([^,]+)") do
          table.insert(names, dns)
        end
      end
      if type(ext) == "table" and ext.name == "X509v3 Subject Alternative Name" then
        if type(ext.value) == "string" then
          for dns in string.gmatch(ext.value, "DNS:([^,]+)") do
            table.insert(names, stdnse.strtrim(dns))
          end
        end
      end
    end
  end
  -- sslcert sometimes exposes cert.subject_alternative_names as a list
  if cert.subject_alternative_name then
    local san = cert.subject_alternative_name
    if type(san) == "table" then
      for _, item in pairs(san) do
        if type(item) == "string" then
          table.insert(names, item)
        elseif type(item) == "table" and item.dNSName then
          table.insert(names, item.dNSName)
        end
      end
    end
  end
  out.names = table.concat(names, ",")
  out.count = tostring(#names)
  return out
end
