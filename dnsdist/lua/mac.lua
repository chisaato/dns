-- =============================================================================
-- mac.lua — MAC 感知设备分流：端 MAC 识别 + 剥离私有 EDNS option
--
-- 从 EDNS option 65001（OpenWRT 私有选项）提取请求端 MAC 地址，
-- 判断该设备是否在需过滤列表（mac-clean.txt）中，供 dnsdist.conf 规则链使用。
-- 同时负责在转发前剥离私有 EDNS 选项，避免上游 DoH 拒绝。
--
-- 只有两类设备：
--   Clean   → 在 mac-clean.txt 中 → 需过滤（走 blacklist → self_doh）
--   非 Clean → 不在列表中（或无 EDNS） → 免过滤（走 self_no_filter → cn_doh）
-- =============================================================================

MAC_OPTION_CODE = 65001

-- =============================================================================
-- 工具函数 — EDNS option payload 提取
-- =============================================================================

-- bytesToMac(raw): 6 字节原始数据 → "xx:xx:xx:xx:xx:xx" 格式（人类可读日志）
function bytesToMac(raw)
  if raw == nil or #raw ~= 6 then return nil end
  return string.format(
    '%02x:%02x:%02x:%02x:%02x:%02x', string.byte(raw, 1), string.byte(raw, 2), string.byte(raw, 3), string.byte(raw, 4),
    string.byte(raw, 5), string.byte(raw, 6)
  )
end

-- macBytesToHex(raw): 6 字节原始数据 → "xxxxxxxxxxxx" 无分隔符 hex
-- 用于 dq:setTag('mac', ...) 和 g_clean_macs 哈希表查找
function macBytesToHex(raw)
  if raw == nil then return nil end
  return string.format(
    '%02x%02x%02x%02x%02x%02x', string.byte(raw, 1), string.byte(raw, 2), string.byte(raw, 3), string.byte(raw, 4),
    string.byte(raw, 5), string.byte(raw, 6)
  )
end

-- getOptionPayload(option): 统一提取 EDNS option 的 payload 内容
--
-- dnsdist 内部对 EDNS option 的表示方式因版本/API 而异：
--   - 纯字符串（payload 本身）
--   - 有 getValues 方法的对象
--   - 带 content / data / value 字段的 table
-- 此函数兼容所有已知格式，确保 getMacOptionPayload 稳定工作。
function getOptionPayload(option)
  if option == nil then return nil end
  if type(option) == 'string' then return option end
  if option.getValues ~= nil then
    local values = option:getValues()
    if values ~= nil and values[1] ~= nil then return values[1] end
  end
  if option.content ~= nil then return option.content end
  if option.data ~= nil then return option.data end
  if option.value ~= nil then return option.value end
  return nil
end

-- getMacOptionPayload(dq): 从 DNSQuestion 的 EDNS options 中提取 65001 的 payload
--
-- pairs(options) 的 key 可能是数字 code（dnsdist 2.1+ 拷贝语义），也可能是
-- 包含 code 字段的 table。两种路径都处理。
function getMacOptionPayload(dq)
  local options = dq:getEDNSOptions()
  if options == nil then return nil end
  for code, option in pairs(options) do
    if tonumber(code) == MAC_OPTION_CODE then
      return getOptionPayload(option)
    end
    if type(option) == 'table' and option.code == MAC_OPTION_CODE then
      return getOptionPayload(option)
    end
  end
  return nil
end

-- getMacBytes(dq): 获取原始 6 字节 MAC 数据，长度不对则返回 nil
function getMacBytes(dq)
  local payload = getMacOptionPayload(dq)
  if payload == nil or #payload ~= 6 then return nil end
  return payload
end

-- =============================================================================
-- 结构化 JSON 日志工具
-- =============================================================================

-- QType 数字 → 字符串映射（常见类型）
QTYPE_NAMES = {
  [1] = 'A', [2] = 'NS', [5] = 'CNAME', [6] = 'SOA', [12] = 'PTR',
  [15] = 'MX', [16] = 'TXT', [28] = 'AAAA', [33] = 'SRV', [41] = 'OPT',
  [43] = 'DS', [44] = 'SSHFP', [46] = 'RRSIG', [47] = 'NSEC', [48] = 'DNSKEY',
  [64] = 'SVCB', [65] = 'HTTPS', [255] = 'ANY',
}

-- qtypeStr(n): 返回 QType 字符串，未知返回 "TYPE{n}"
function qtypeStr(n)
  return QTYPE_NAMES[n] or ('TYPE' .. tostring(n))
end

-- jsonEscape(s): 转义 JSON 字符串中的特殊字符
function jsonEscape(s)
  if s == nil then return '' end
  return (s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t'))
end

-- logJson(event, fields, level): 输出结构化 JSON 日志
--   event  — 事件类型字符串（如 "query" / "resp" / "mac"）
--   fields — { {key, value}, {key, value}, ... }（有序排列）
--   level  — 日志级别：'info'（默认）/ 'warn' / 'err'
function logJson(event, fields, level)
  level = level or 'info'
  local parts = {'{"e":"' .. jsonEscape(event) .. '"'}
  for _, item in ipairs(fields) do
    parts[#parts+1] = ',"' .. jsonEscape(item[1]) .. '":'
    local v = item[2]
    if v == nil then
      parts[#parts+1] = 'null'
    elseif type(v) == 'string' then
      parts[#parts+1] = '"' .. jsonEscape(v) .. '"'
    elseif type(v) == 'number' then
      if v == math.floor(v) then
        parts[#parts+1] = tostring(math.floor(v))
      else
        parts[#parts+1] = string.format('%.3f', v)
      end
    elseif type(v) == 'boolean' then
      parts[#parts+1] = v and 'true' or 'false'
    else
      parts[#parts+1] = 'null'
    end
  end
  parts[#parts+1] = '}'
  local msg = table.concat(parts)
  if level == 'warn' then
    warnlog(msg)
  elseif level == 'err' then
    errlog(msg)
  else
    infolog(msg)
  end
end

-- setActionTags(dq, rule, pool): 为下游响应日志设置 tag
function setActionTags(dq, rule, pool)
  dq:setTag('rule_hit', rule or '')
  if pool then dq:setTag('pool_selected', pool) end
end

-- getMacReadable(dq): 从 mac tag 获取可读 MAC 地址（"aa:bb:cc:dd:ee:ff"）
function getMacReadable(dq)
  local mac = dq:getTag('mac')
  if mac == nil or mac == '' or mac == 'default-clean' then return '' end
  return mac:gsub('(..)', '%1:'):gsub(':$', '')
end

-- getDeviceType(dq): 从 mac tag 推断设备类型（"clean" / "no_filter" / ""）
function getDeviceType(dq)
  local mac = dq:getTag('mac')
  if mac == nil or mac == '' then return '' end
  if mac == 'default-clean' then return 'clean' end
  return g_clean_macs[mac] and 'clean' or 'no_filter'
end

-- =============================================================================
-- 全局状态 — Clean 设备 MAC 哈希表
-- =============================================================================
-- 以无分隔符 hex（如 "047c16bf923c"）为 key，true 为 value。
-- 在 loadDevices() 时通过加载 mac-clean.txt 填充。

g_clean_macs = {}

-- =============================================================================
-- 设备列表加载
-- =============================================================================

-- loadMacList(path, hash): 从文本文件加载 MAC 列表到指定哈希表
-- 每行一个 MAC，支持两种格式：
--   冒号分割  aa:bb:cc:dd:ee:ff（推荐，与云端下发格式一致）
--   纯 hex    aabbccddeeff（兼容）
-- 内部统一存储为纯 hex（12 字符）。自动去除首尾空白。
-- 返回加载条数。
function loadMacList(path, hash)
  local f = io.open(path, 'r')
  if f == nil then
    warnlog('mac: 无法打开 ' .. path)
    return 0
  end
  local count = 0
  for line in f:lines() do
    line = line:match('^%s*(%S+)%s*$')
    if line == nil or line == '' then goto continue end
    -- 统一为纯 hex：去掉冒号
    local hex = line:gsub(':', '')
    if #hex == 12 then
      hash[hex] = true
      count = count + 1
    end
    ::continue::
  end
  f:close()
  return count
end

-- loadDevices(): 加载"需过滤设备"列表 → g_clean_macs
function loadDevices()
  local count = loadMacList('/etc/dnsdist/lists/mac-clean.txt', g_clean_macs)
  infolog('mac: 加载了 ' .. count .. ' 个 clean 设备 MAC')
end

-- =============================================================================
-- Phase 1 — MAC 观测 + 剥离（作为第一条 addAction 调用）
-- =============================================================================

-- observeMacOption65001(dq): 核心观测动作
--
-- 1. 从 EDNS option 65001 提取 MAC 地址
-- 2. 日志输出人类可读格式（edns65001_mac_found=xx:xx:xx:xx:xx:xx）
-- 3. 将 hex MAC 存入 dq:setTag('mac', ...) 供下游 isClean / isNoFilter 使用
-- 4. 移除 EDNS 65001 — 避免上游 DoH 因无法识别私有选项而返回 HTTP 502
--
-- 返回 DNSAction.None 以继续匹配后续规则。
function observeMacOption65001(dq)
  -- 仅对 1853 端口做 MAC 观测（1753 是不走分流的端口）
  local localStr = dq.localaddr:toStringWithPort()
  if not localStr:match(':1853$') then
    return DNSAction.None
  end

  local raw = getMacBytes(dq)
  if raw ~= nil then
    local hex = macBytesToHex(raw)
    local mac = bytesToMac(raw)
    -- 保存 MAC 为 tag，供下游 isClean / isNoFilter 使用
    dq:setTag('mac', hex)
    logJson('mac', {
      {'mac', mac},
      {'src_edns', true},
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
    })
    -- 转发前剥离 EDNS 65001，避免上游 DoH 拒绝
    local ok, err = pcall(function ()
        dq:removeEDNSOption(MAC_OPTION_CODE)
      end)
    if not ok then
      logJson('err', {{'msg', '剥离 EDNS 65001 失败'}, {'err', tostring(err)}}, 'warn')
    end
  else
    -- 无 EDNS 65001 → 默认视为 Clean 设备，走 blocklist → self_doh
    dq:setTag('mac', 'default-clean')
    logJson('mac', {
      {'src_edns', false},
      {'note', 'default_clean'},
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
    })
  end
  return DNSAction.None
end

-- =============================================================================
-- 规则命中日志包装
-- =============================================================================

-- logPoolHit(msg, pool): 记录日志并转发到指定 pool
function logPoolHit(msg, pool)
  return LuaAction(function(dq)
    setActionTags(dq, msg, pool)
    logJson('query', {
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
      {'qtype_s', qtypeStr(dq.qtype)},
      {'src', dq.remoteaddr:toStringWithPort()},
      {'mac', getMacReadable(dq)},
      {'dev', getDeviceType(dq)},
      {'rule', msg},
      {'action', 'pool'},
      {'pool', pool},
      {'port', tonumber(dq.localaddr:toStringWithPort():match(':(%d+)$')) or 0},
      {'proto', dq:getProtocol()},
    })
    return DNSAction.Pool, pool
  end)
end

-- logRcodeHit(msg, rcode): 记录日志并返回 NXDOMAIN
function logRcodeHit(msg, rcode)
  return LuaAction(function(dq)
    setActionTags(dq, msg)
    logJson('query', {
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
      {'qtype_s', qtypeStr(dq.qtype)},
      {'src', dq.remoteaddr:toStringWithPort()},
      {'mac', getMacReadable(dq)},
      {'dev', getDeviceType(dq)},
      {'rule', msg},
      {'action', 'nxdomain'},
      {'port', tonumber(dq.localaddr:toStringWithPort():match(':(%d+)$')) or 0},
      {'proto', dq:getProtocol()},
    })
    return DNSAction.NXDOMAIN
  end)
end

-- logSpoofHit(msg): 记录日志并返回 zero-IP
function logSpoofHit(msg)
  return LuaAction(function(dq)
    setActionTags(dq, msg)
    logJson('query', {
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
      {'qtype_s', qtypeStr(dq.qtype)},
      {'src', dq.remoteaddr:toStringWithPort()},
      {'mac', getMacReadable(dq)},
      {'dev', getDeviceType(dq)},
      {'rule', msg},
      {'action', 'spoof'},
      {'port', tonumber(dq.localaddr:toStringWithPort():match(':(%d+)$')) or 0},
      {'proto', dq:getProtocol()},
    })
    -- DNSAction.Spoof 需要第二个参数指定伪造 IP，按查询类型返回对应的 zero-IP
    if dq.qtype == 28 then
      return DNSAction.Spoof, '::'
    else
      return DNSAction.Spoof, '0.0.0.0'
    end
  end)
end

-- logRouteHit(msg, routeFunc): 记录日志并执行路由函数
function logRouteHit(msg, routeFunc)
  return LuaAction(function(dq)
    setActionTags(dq, msg)
    logJson('query', {
      {'qname', dq.qname:toString():gsub('%.$', '')},
      {'qtype', dq.qtype},
      {'qtype_s', qtypeStr(dq.qtype)},
      {'src', dq.remoteaddr:toStringWithPort()},
      {'mac', getMacReadable(dq)},
      {'dev', getDeviceType(dq)},
      {'rule', msg},
      {'action', 'route'},
      {'port', tonumber(dq.localaddr:toStringWithPort():match(':(%d+)$')) or 0},
      {'proto', dq:getProtocol()},
    })
    return routeFunc(dq)
  end)
end

-- =============================================================================
-- MAC 设备分类
-- =============================================================================

-- isClean(dq): 是否需过滤设备（走 blocklist → self_doh）
-- 以下情况返回 true：
--   - 携带 EDNS 65001 且 MAC 在 mac-clean.txt 中
--   - 1853 端口未携带 EDNS 65001（默认 clean）
-- 1753 端口无 tag（observe 跳过），始终返回 false
function isClean(dq)
  local hex = dq:getTag('mac')
  if hex == '' or hex == nil then return false end
  if hex == 'default-clean' then return true end
  return g_clean_macs[hex] == true
end

-- isNoFilter(dq): 是否为免过滤设备（走 self_no_filter → cn_doh）
-- 以下情况返回 true：
--   - 1753 端口（无 tag）
--   - 携带 EDNS 65001 但 MAC 不在 mac-clean.txt 中
-- 1853 无 EDNS 时返回 false（标记为 default-clean，视为需过滤）
function isNoFilter(dq)
  local hex = dq:getTag('mac')
  if hex == '' or hex == nil then return true end
  if hex == 'default-clean' then return false end
  return not g_clean_macs[hex]
end
