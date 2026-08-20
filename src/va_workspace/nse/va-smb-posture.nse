local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Unauthenticated SMB posture: OS/domain if offered, share list via null
session, and a signing/dialect hint when the smb library exposes it.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = smb.get_port

action = function(host)
  local out = stdnse.output_table()

  local ok_os, osinfo = pcall(smb.get_os, host)
  if ok_os and type(osinfo) == "table" then
    out.os = osinfo.os or osinfo.lanmanager or ""
    out.domain = osinfo.domain or osinfo.dns_domain or ""
    out.server = osinfo.server or ""
  elseif ok_os and type(osinfo) == "string" then
    out.os = osinfo
  end

  local ok_shares, shares = pcall(smb.share_get_list, host)
  if ok_shares and type(shares) == "table" then
    local names = {}
    local anon = {}
    for _, share in ipairs(shares) do
      local name = share.name or share[1] or tostring(share)
      table.insert(names, name)
      if share.user_can_read or share.anonymous then
        table.insert(anon, name)
      end
    end
    out.shares = table.concat(names, ",")
    if #anon > 0 then
      out.anonymous_shares = table.concat(anon, ",")
    else
      out.anonymous_shares = ""
    end
  else
    out.shares = ""
    if not ok_shares then
      out.share_error = tostring(shares)
    end
  end

  -- Signing is not always exposed; record whatever get_os gave us.
  if osinfo and type(osinfo) == "table" and osinfo.signing then
    out.signing = tostring(osinfo.signing)
  end

  return out
end
