-- =============================================================================
-- server.lua — 上游服务器构造器
--
-- 提供 dohServer() 和 addUpstream() 两个函数。
-- dohServer()      — 传统方式，domain + pool + port + path + name
-- addUpstream()    — URL 驱动，自动识别协议并适配
--
-- 通过内建 resolveViaDoHFirst() 将上游域名解析为 IP，
-- 不依赖系统 DNS（无明文 UDP:53）。
-- =============================================================================

-- DoH 引导端点：纯 IP DoH，用于解析上游域名
local BS = {
  'https://223.5.5.5/dns-query',
  'https://223.6.6.6/dns-query',
  'https://1.12.12.12/dns-query',
  'https://120.53.53.53/dns-query'
  -- 腾讯不使用下面这个 IP 提供 DoH
  -- 'https://119.29.29.29/dns-query',
}

-- =============================================================================
-- addUpstream(url, pool, name) — URL 驱动创建上游服务器
--
-- URL 格式：
--   无协议头 / udp://   → 明文 UDP   默认端口 53
--   tcp://              → 明文 TCP   默认端口 53
--   tls://              → DoT        默认端口 853
--   https://            → DoH        默认端口 443 路径 /dns-query
--   h3://               → DoH3       默认端口 443 路径 /dns-query
--   quic://             → DoQ        默认端口 853
--
-- pool:  所属池名
-- name:  可选，服务器标识名（自动从 URL 生成）
--
-- 用法：
--   addUpstream('https://doh.pub/dns-query', 'cn_doh')
--   addUpstream('quic://seek.zerodream.net:4215', 'self_doh')
--   addUpstream('192.168.1.1:53', 'hijack')
-- =============================================================================

-- parseUpstreamUrl(url): 解析上游 URL，返回 proto, host, port, path
local function parseUpstreamUrl(url)
  -- 匹配协议头
  local proto, rest = url:match('^(%w+)://(.+)$')

  if proto == nil then
    -- 无协议头 → 默认 UDP（兼容 "host:port" 格式）
    local host, port = url:match('^%[(.+)%]:(%d+)$')
    if host then return 'udp', host, tonumber(port), nil end
    host, port = url:match('^([^:]+):(%d+)$')
    if host then return 'udp', host, tonumber(port), nil end
    return 'udp', url, 53, nil
  end

  -- HTTPS / H3：https://host:port/path
  if proto == 'https' or proto == 'h3' then
    local host, port, path = rest:match('^([^:/]+):(%d+)(/.*)$')
    if host then return proto, host, tonumber(port), path end
    host, path = rest:match('^([^:/]+)(/.*)$')
    if host then return proto, host, 443, path end
    host, port = rest:match('^([^:]+):(%d+)$')
    if host then return proto, host, tonumber(port), '/dns-query' end
    return proto, rest, 443, '/dns-query'
  end

  -- QUIC / TLS：quic://host:port  tls://host:port
  if proto == 'quic' or proto == 'tls' then
    local host, port = rest:match('^([^:]+):(%d+)$')
    if host then return proto, host, tonumber(port), nil end
    return proto, rest, 853, nil
  end

  -- TCP / UDP：tcp://host:port  udp://host:port
  if proto == 'tcp' or proto == 'udp' then
    local host, port = rest:match('^([^:]+):(%d+)$')
    if host then return proto, host, tonumber(port), nil end
    return proto, rest, 53, nil
  end

  warnlog("addUpstream: 未知协议 '" .. proto .. "' — " .. url)
  return nil, nil, nil, nil
end

-- addUpstream(url, pool, name): 解析 URL 并创建 dnsdist 上游服务器
function addUpstream(url, pool, name)
  local proto, host, port, path = parseUpstreamUrl(url)
  if host == nil then
    errlog("addUpstream: 无法解析 '" .. tostring(url) .. "'")
    return
  end

  if name == nil then
    name = (host:gsub('%.', '-')) .. '-' .. proto
  end

  -- ── 加密协议：解析域名（双栈全量）→ 每个 IP 建一条服务器 ──
  if proto == 'https' or proto == 'h3' or proto == 'quic' or proto == 'tls' then
    -- QUIC 出方向暂不支持（dnsdist 2.1.x），静默跳过
    if proto == 'quic' then
      infolog("addUpstream: 跳过 quic://" .. host .. " — 当前版本不支持 DoQ 出方向")
      return
    end

    local ips
    if host:match('^%d+%.%d+%.%d+%.%d+$') or host:match(':') then
      -- host 已是纯 IP，跳过 DoH bootstrap
      ips = { host }
      infolog("addUpstream: " .. host .. " 已是 IP,跳过解析")
    else
      infolog("addUpstream: 正在解析 " .. host .. " ...")
      ips = resolveViaDoH(host, BS)
    end
    if ips == nil or #ips == 0 then
      errlog("addUpstream: 解析失败 '" .. host .. "' — 无返回 IP")
      return
    end

    infolog("addUpstream: " .. host .. " 解析到 " .. #ips .. " 个 IP:")
    for i, ip in ipairs(ips) do
      infolog("  [" .. i .. "] " .. ip)
    end

    for idx, ip in ipairs(ips) do
      local suffix = ip:match(':') and '-6' or '-4' -- IPv6 后缀 -6, IPv4 后缀 -4
      local params = {
        address = ip .. ':' .. port,
        name = name .. suffix,
        tls = 'openssl',
        subjectName = host,
        pool = pool,
        -- 健康检测间隔(秒)，设为 0 可临时禁用
        checkInterval = 30,
        -- 使用更常见的域名来解析
        checkName = 'www.baidu.com',
        -- 傻逼玩意 AI 在这里幻觉写了个 1 虽然 A 记录确实在二进制里是 id 为 1.
        -- 但是这里要求传入字符串,所以直接进行了一个非法查询.
        checkType = 'A',
        -- 我觉得超时可以多一点
        checkTimeout = 5,
        rise = 1,
        -- 临时禁用证书验证
        -- validateCertificates = false,
        keyLogFile = '/etc/dnsdist/dnsdist.keylog',
        fall = 5
      }

      if proto == 'https' or proto == 'h3' then
        params.dohPath = path
        infolog("设定 doh 路径 " .. path)
        if proto == 'h3' then
          params.dohProtocol = 'h3'
        end
      end
      -- tls: 无需额外参数

      newServer(params)
    end

    infolog(
      "addUpstream: " .. proto .. "://" .. host .. path .. " → " .. pool .. " (" .. tostring(#ips) .. " 个 IP)"
    )
    return
  end

  -- ── 明文协议：无需域名解析 ──
  if proto == 'tcp' then
    newServer({
      address = host .. ':' .. port,
      name = name,
      pool = pool,
      tcp = true,
      checkInterval = 10
    })
    infolog("addUpstream: tcp://" .. host .. " → " .. pool)
    return
  end

  -- UDP（默认）
  newServer({
    address = host .. ':' .. port,
    name = name,
    pool = pool,
    checkInterval = 10
  })
  infolog("addUpstream: " .. host .. " → " .. pool .. " (udp)")
end

-- =============================================================================
-- dohServer(domain, pool, port, path, name) — 传统方式创建 DoH 上游
--
-- 保留向后兼容，新代码建议用 addUpstream()。
-- =============================================================================
function dohServer(domain, pool, port, path, name)
  local ips
  if domain:match('^%d+%.%d+%.%d+%.%d+$') or domain:match(':') then
    ips = { domain }
  else
    ips = resolveViaDoH(domain, BS)
  end
  if ips == nil or #ips == 0 then
    errlog("dohServer: 无法解析 '" .. domain .. "'")
    return
  end
  for idx, ip in ipairs(ips) do
    local suffix = ip:match(':') and '-6' or '-4'
    newServer({
      address = ip .. ':' .. (port or 443),
      name = (name or domain) .. suffix,
      tls = 'openssl',
      subjectName = domain,
      dohPath = path or '/dns-query',
      pool = pool,
      checkInterval = 30 -- 设为 0 可临时禁用健康检测
    })
  end
  infolog("dohServer: " .. domain .. " → " .. pool .. " (" .. tostring(#ips) .. " 个 IP)")
end
