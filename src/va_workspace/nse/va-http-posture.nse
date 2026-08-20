local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Focused unauthenticated HTTP snapshot for CHECK ITHCs: title, security
headers, cookie flags, TRACE, and OPTIONS methods in one script.
]]

author = "va-workspace"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "va"}

portrule = shortport.http

local SECURITY_HEADERS = {
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
}

local function header(resp, name)
  if not resp or not resp.header then
    return nil
  end
  return resp.header[name] or resp.header[string.lower(name)]
end

local function title_from(body)
  if not body then
    return nil
  end
  local t = string.match(body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]+)")
  if t then
    t = string.gsub(t, "%s+", " ")
    return string.sub(stdnse.string_or_blank(t), 1, 120)
  end
  return nil
end

local function cookie_issues(set_cookie)
  if not set_cookie or set_cookie == "" then
    return "none"
  end
  local blob = string.lower(set_cookie)
  local issues = {}
  if not string.find(blob, "httponly", 1, true) then
    table.insert(issues, "missing-httponly")
  end
  if not string.find(blob, "secure", 1, true) then
    table.insert(issues, "missing-secure")
  end
  if #issues == 0 then
    return "ok"
  end
  return table.concat(issues, ",")
end

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/", {timeout = 8000})
  if not resp then
    out.error = "no http response"
    return out
  end

  out.status = tostring(resp.status or "")
  out.server = header(resp, "server") or ""
  out.title = title_from(resp.body) or ""
  out.location = header(resp, "location") or ""

  local missing = {}
  for _, name in ipairs(SECURITY_HEADERS) do
    if not header(resp, name) then
      table.insert(missing, name)
    end
  end
  if #missing > 0 then
    out.hsts = "missing"
    out.missing_headers = table.concat(missing, ",")
  else
    out.hsts = "present"
    out.missing_headers = ""
  end

  out.cookies = cookie_issues(header(resp, "set-cookie"))

  local xff = header(resp, "x-forwarded-for") or header(resp, "x-real-ip") or ""
  if string.match(xff, "10%.%d+") or string.match(xff, "192%.168%.") or string.match(xff, "172%.%d+%.") then
    out.internal_ip = xff
  else
    out.internal_ip = ""
  end

  local trace = http.generic_request(host, port, "TRACE", "/", {timeout = 5000})
  if trace and trace.status and trace.status < 400 then
    out.trace = "enabled"
  else
    out.trace = "disabled"
  end

  local opt = http.generic_request(host, port, "OPTIONS", "/", {timeout = 5000})
  local allow = opt and header(opt, "allow") or ""
  out.methods = allow
  if string.match(string.upper(allow), "PUT") or string.match(string.upper(allow), "DELETE")
      or string.match(string.upper(allow), "TRACE") or string.match(string.upper(allow), "CONNECT") then
    out.dangerous_methods = "yes"
  else
    out.dangerous_methods = "no"
  end

  return out
end
