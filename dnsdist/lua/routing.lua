-- =============================================================================
-- routing.lua — 自建上游健康检查 + 托底分裂路由
--
-- 提供两个路由函数，供 dnsdist.conf 的 LuaAction 规则使用：
--   routeSelfDohOrFallback(dq)    — Clean 设备：先试 self_doh，不可用则本地 CN 分裂
--   routeNoFilterOrFallback(dq)   — 免过滤设备：先试 self_no_filter，不可用则 cn_doh
--
-- 健康检查原理：通过 getPool():getServers() 枚举池内服务器，
-- 调用 s:isUp() 检查是否至少有一台可用。全部不可用时走托底路径。
-- 所有 API 调用均用 pcall() 包裹，兼容不同 dnsdist 版本。
-- =============================================================================

-- poolHasAvailable(poolName): 检查指定池是否有至少一台可用服务器
-- 返回 true = 有可用服务器，false = 全部不可用或检查失败
local function poolHasAvailable(poolName)
  local ok, poolServers = pcall(getPoolServers, poolName)
  if not ok then
    warnlog('健康检查: getPoolServers(' .. poolName .. ') 失败: ' .. tostring(poolServers))
    return false
  end
  if poolServers == nil then
    warnlog('健康检查: pool ' .. poolName .. ' 为 nil')
    return false
  end

  local total = 0
  local upCount = 0
  for _, s in ipairs(poolServers) do
    total = total + 1
    local ok3, up = pcall(function() return s:isUp() end)
    if ok3 and up then
      upCount = upCount + 1
    end
  end

  if total == 0 then
    warnlog('健康检查: pool ' .. poolName .. ' 无服务器')
    return false
  end

  if upCount == 0 then
    warnlog('健康检查: pool ' .. poolName .. ' 全部不可用 (0/' .. total .. ')')
    return false
  end

  infolog('健康检查: pool ' .. poolName .. ' 可用 (' .. upCount .. '/' .. total .. ')')
  return true
end

-- routeSelfDohOrFallback(dq): Clean 设备路由
--
-- 正常：self_doh（自建公网 AdGuard，带过滤功能）
-- 托底：self_doh 全部不可用时，本地模拟公网 AdGuard 分裂：
--   CN 域名 → cn_doh（国内公共 DoH）
--   非 CN  → overseas_doh（CF 隧道反代）
function routeSelfDohOrFallback(dq)
  local qname = dq.qname:toString()
  local src = dq.remoteaddr:toString()

  if poolHasAvailable('self_doh') then
    infolog('转发: ' .. qname .. ' [' .. src .. '] → self_doh')
    return DNSAction.Pool, 'self_doh'
  end

  -- 托底：本地分裂
  if cnDomains:check(dq.qname) then
    infolog('转发: ' .. qname .. ' [' .. src .. '] → cn_doh (self_doh 不可用, CN 域名)')
    return DNSAction.Pool, 'cn_doh'
  end
  infolog('转发: ' .. qname .. ' [' .. src .. '] → overseas_doh (self_doh 不可用, 非 CN)')
  return DNSAction.Pool, 'overseas_doh'
end

-- routeNoFilterOrFallback(dq): 免过滤设备路由
--
-- 正常：self_no_filter（自建无过滤 DoH）
-- 托底：全部不可用时走 cn_doh（国内公共 DoH）
function routeNoFilterOrFallback(dq)
  local qname = dq.qname:toString()
  local src = dq.remoteaddr:toString()

  if poolHasAvailable('self_no_filter') then
    infolog('转发: ' .. qname .. ' [' .. src .. '] → self_no_filter')
    return DNSAction.Pool, 'self_no_filter'
  end
  infolog('转发: ' .. qname .. ' [' .. src .. '] → cn_doh (self_no_filter 不可用)')
  return DNSAction.Pool, 'cn_doh'
end

-- =============================================================================
-- build_hijack(name, upstream, blockHttps) — 构建本地劫持规则
--
-- 参数：
--   name:       劫持名称，用于拼接域名列表文件名 hijack-{name}.txt 和 pool 名
--   upstream:   上游服务器地址数组，如 {"192.168.1.1:53", "10.0.0.1:53"}
--   blockHttps: 是否阻断 QTYPE 65（默认 true，不传则启用）
--
-- 行为：
--   1. 从 /etc/dnsdist/lists/hijack-{name}.txt 加载域名列表
--   2. 创建上游服务器（pool = hijack_{name}）
--   3. 如果 blockHttps 则添加 QTYPE 65 → NXDOMAIN 规则
--   4. 添加劫持域名 → 该 pool 的路由规则
--   5. 不区分 MAC，对所有 LAN 设备生效（须在 MAC 分流前调用）
--
-- 用法（在 dnsdist.conf 中）：
--   build_hijack('internal', {'192.168.1.1:53'}, true)
-- =============================================================================
function build_hijack(name, upstream, blockHttps)
  if blockHttps == nil then blockHttps = true end
  if name == nil or type(upstream) ~= 'table' or #upstream == 0 then
    warnlog("hijack: 跳过 '" .. tostring(name) .. "' — 参数无效")
    return
  end

  -- 生成 pool 名和域名列表文件路径
  local poolName = 'hijack_' .. name:gsub('[^%w_]', '_')
  local listPath = '/etc/dnsdist/lists/hijack-' .. name .. '.txt'

  -- 加载域名列表
  local node = loadDomainList(listPath)
  if node == nil then
    warnlog("hijack: '" .. name .. "' — 列表文件不存在或为空，劫持不生效")
    node = newSuffixMatchNode()
  end

  -- 添加上游服务器
  for _, addr in ipairs(upstream) do
    newServer({
      address = addr,
      pool = poolName,
      name = 'hijack-' .. name,
      checkInterval = 10,
    })
  end

  -- 添加规则：先阻断 QTYPE 65，再路由到劫持服务器
  if blockHttps then
    addAction(SuffixMatchNodeRule(node) .. QTypeRule(65), RCodeAction(3))
  end
  addAction(SuffixMatchNodeRule(node), PoolAction(poolName))

  infolog("hijack: 已构建 '" .. name .. "' — " .. tostring(#upstream) .. " 台服务器, " .. (blockHttps and "阻断 QTYPE65" or "不阻断 QTYPE65"))
end
