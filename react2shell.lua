-- React2Shell PRO Detector v2 (cleaned)
local http     = require "http"
local cjson    = require "cjson"
local stdnse   = require "stdnse"
local shortport= require "shortport"
local string   = require "string"
local table    = require "table"

description = [[
React2Shell PRO Detector v2 (detection-only).
Enhanced detection of React SSR/RSC Flight serialization and unsafe deserialization indicators.
This script performs safe, passive checks and non-exploitive POST probes.
]]

author = "saad ayady | 0xdy"
license = "Same as Nmap"
categories = {"safe","discovery","vuln"}

-- Run on common HTTP ports/services
portrule = shortport.port_or_service(
  {80, 443, 3000, 3001, 4200, 5000, 8000, 8080, 9000},
  {"http", "https"}
)

-- Indicators grouped by priority
local indicators = {
  strong = {
    "%$%$typeof", "_owner", "_store", "_reactInternals", "_debugSource",
    "_debugOwner", "elementType", "fiber", "stateNode", "tag", "mode",
    "flags", "\"key\"", "\"ref\""
  },
  rsc = {
    '"%$"', "%$L%d+", '%$id', '%$type', '%$ref', "clientReference",
    "serverReference", "react%.server", "\"use client\"", "\"use server\""
  },
  props = {
    '"props"%s*:', '"children"%s*%[', '"children"%s*:', "defaultProps",
    "contextTypes", "propTypes"
  },
  dev = {
    "reactDevTools", "development", "__DEV__", "componentStack", "stack"
  }
}

-- Endpoints to probe (GET)
local endpoints = {
  "/", "/index", "/home", "/app",
  "/api", "/api/v1", "/api/v2",
  "/graphql", "/graphiql",
  "/render", "/ssr", "/_render", "/_ssr",
  "/_next", "/_next/data", "/_next/static", "/_next/server",
  "/rsc", "/_rsc", "/_flight", "/react", "/_react", "/server",
  "/api/rsc", "/api/flight", "/test", "/debug", "/health", "/status"
}

-- POST endpoints to test (safe, non-exploitative)
local post_endpoints = { "/api", "/graphql", "/rsc", "/_flight", "/render" }

-- Heuristic: quick JSON-like detection
local function is_react_json(body)
  if not body or #body < 20 then return false end
  local first = body:sub(1,1)
  if first ~= "{" and first ~= "[" then return false end

  -- light-weight patterns
  if body:find('"props"') or body:find('"children"') or body:find("%$%$typeof") then
    return true
  end
  return false
end

-- Weighted scoring of a response body
local function score_response(body, endpoint)
  local s = { strong=0, rsc=0, props=0, dev=0, total=0 }
  if not body then return s end

  -- count occurrences (using Lua patterns)
  for _, pat in ipairs(indicators.strong) do
    local _, cnt = body:gsub(pat, "")
    s.strong = s.strong + (cnt * 3)
  end
  for _, pat in ipairs(indicators.rsc) do
    local _, cnt = body:gsub(pat, "")
    s.rsc = s.rsc + (cnt * 2)
  end
  for _, pat in ipairs(indicators.props) do
    local _, cnt = body:gsub(pat, "")
    s.props = s.props + (cnt * 1)
  end
  for _, pat in ipairs(indicators.dev) do
    local _, cnt = body:gsub(pat, "")
    s.dev = s.dev + (cnt * 1)
  end

  -- endpoint bonuses
  if endpoint:find("rsc") or endpoint:find("flight") then
    s.total = s.total + 5
  elseif endpoint:find("render") or endpoint:find("ssr") then
    s.total = s.total + 3
  end

  s.total = s.total + s.strong + s.rsc + s.props + s.dev
  return s
end

-- Try to extract React versions from page/bundles
local function extract_react_version(body)
  if not body then return nil end
  local patterns = {
    "React v(%d+%.%d+%.%d+)",
    "react@(%d+%.%d+%.%d+)",
    '"react"%s*:%s*"(%-?%d+%.%d+%.%d+)"',
    "React%-(%d+%.%d+%.%d+)"
  }
  for _, p in ipairs(patterns) do
    local v = body:match(p)
    if v then return v end
  end
  return nil
end

-- Safe passive POST deserialization probes (non-exploitative)
local function test_post_deserialization(host, port, endpoint)
  local test_payloads = {
    '{"test":1}',
    '{"$type":"test"}',
    '{"$$typeof":"test"}',
    '{"props":{"__test":true}}',
    '["$","div",null,{"children":"test"}]'
  }

  local opts = {
    header = {
      ["Content-Type"] = "application/json",
      ["User-Agent"] = "React2Shell-Tester/2.0"
    }
  }

  for _, payload in ipairs(test_payloads) do
    -- correct http.post signature: http.post(host, port, path, body, options)
    local r = http.post(host, port, endpoint, payload, opts)
    if r and (r.status == 400 or r.status == 500) then
      local low = (r.body or ""):lower()
      local errors = { "decode", "deserializ", "unexpected token", "json parse",
                       "%$type", "invalid element", "flight", "react.server", "malformed" }
      for _, e in ipairs(errors) do
        if low:find(e) then
          return true, payload, (r.body or ""):sub(1,200)
        end
      end
    end
  end

  return false, nil, nil
end

action = function(host, port)
  stdnse.print_debug(1, "[React2Shell PRO v2] Scanning %s:%d", host.ip, port.number)

  local findings = {}
  local total_score = 0
  local react_version = nil

  -- Phase 1: GET probe
  for _, ep in ipairs(endpoints) do
    local r = http.get(host, port, ep, { header = { ["User-Agent"] = "Mozilla/5.0 (React2Shell-Scanner/2.0)" } })
    if r and r.status == 200 and r.body and #r.body > 80 then
      if is_react_json(r.body) then
        local scores = score_response(r.body, ep)
        if scores.total >= 5 then
          local snippet = r.body:sub(1, 300):gsub("\n"," "):gsub("\r"," ")
          table.insert(findings, { endpoint = ep, method = "GET", status = r.status, scores = scores, snippet = snippet, size = #r.body })
          total_score = total_score + scores.total
          if not react_version then react_version = extract_react_version(r.body) end
        end
      end
    end
    stdnse.sleep(0.02) -- small throttle
  end

  -- Phase 2: Safe POST probes
  for _, ep in ipairs(post_endpoints) do
    local ok, payload, resp = test_post_deserialization(host, port, ep)
    if ok then
      table.insert(findings, { endpoint = ep, method = "POST", status = "DESERIALIZATION-ERROR", deserialization = { payload = payload, response = resp }, scores = { total = 12 } })
      total_score = total_score + 12
    end
    stdnse.sleep(0.02)
  end

  if #findings == 0 then
    return stdnse.format_output(true, "No React2Shell indicators detected.")
  end

  -- sort findings by score desc
  table.sort(findings, function(a,b) local sa=(a.scores and a.scores.total or 0) local sb=(b.scores and b.scores.total or 0) return sa>sb end)

  -- Build report
  local report = {}
  table.insert(report, string.rep("=", 60))
  table.insert(report, "REACT2SHELL PRO DETECTOR v2 - RESULTS")
  table.insert(report, string.rep("=", 60))
  table.insert(report, string.format("Target: %s:%d", host.ip, port.number))
  table.insert(report, string.format("Findings: %d | Total Score: %d", #findings, total_score))
  if react_version then table.insert(report, string.format("Detected React Version: %s", react_version)) end
  table.insert(report, "")

  local risk = "LOW"
  local emoji = "🟢"
  if total_score >= 30 then risk="CRITICAL" emoji="🔴"
  elseif total_score >= 20 then risk="HIGH" emoji="🟠"
  elseif total_score >= 10 then risk="MEDIUM" emoji="🟡" end
  table.insert(report, string.format("%s RISK: %s", emoji, risk))
  table.insert(report, "")

  for i, f in ipairs(findings) do
    if i <= 6 then
      table.insert(report, string.rep("-", 40))
      table.insert(report, string.format("Finding #%d", i))
      table.insert(report, string.format("Endpoint: %s [%s]", f.endpoint, f.method or "GET"))
      table.insert(report, string.format("Status: %s", tostring(f.status or "N/A")))
      if f.scores then
        table.insert(report, string.format("Score: %d (total)", f.scores.total or 0))
      end
      if f.deserialization then
        table.insert(report, "🚨 DESERIALIZATION INDICATOR")
        table.insert(report, string.format("Payload: %s", f.deserialization.payload or "N/A"))
        table.insert(report, string.format("Response (snippet): %s", f.deserialization.response or "N/A"))
      end
      if f.snippet then
        table.insert(report, string.format("Snippet: %s...", f.snippet))
      end
      table.insert(report, "")
    end
  end

  table.insert(report, string.rep("=", 60))
  table.insert(report, "RECOMMENDATIONS:")
  table.insert(report, "- Update React to latest stable (if applicable)")
  table.insert(report, "- Audit and sanitize server-side deserialization paths")
  table.insert(report, "- Limit public exposure of bundle/package endpoints")
  table.insert(report, "- Monitor and rate-limit suspicious POST payloads")
  table.insert(report, string.rep("=", 60))

  return stdnse.format_output(true, report)
end
