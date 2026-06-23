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
  return string.format('%02x:%02x:%02x:%02x:%02x:%02x',
    string.byte(raw, 1), string.byte(raw, 2), string.byte(raw, 3),
    string.byte(raw, 4), string.byte(raw, 5), string.byte(raw, 6))
end

-- macBytesToHex(raw): 6 字节原始数据 → "xxxxxxxxxxxx" 无分隔符 hex
-- 用于 dq:setTag('mac', ...) 和 g_clean_macs 哈希表查找
function macBytesToHex(raw)
  if raw == nil then return nil end
  return string.format('%02x%02x%02x%02x%02x%02x',
    string.byte(raw, 1), string.byte(raw, 2), string.byte(raw, 3),
    string.byte(raw, 4), string.byte(raw, 5), string.byte(raw, 6))
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
    warnlog('mac: cannot open ' .. path)
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
  infolog('mac: loaded ' .. count .. ' clean device MACs')
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
    infolog('edns65001_mac_found=' .. mac)
    -- 保存 MAC 为 tag，供下游 isClean / isNoFilter 使用
    dq:setTag('mac', hex)
    -- 转发前剥离 EDNS 65001，避免上游 DoH 拒绝
    local ok, err = pcall(function() dq:removeEDNSOption(MAC_OPTION_CODE) end)
    if not ok then
      warnlog('mac: removeEDNSOption failed: ' .. tostring(err))
    end
  else
    infolog('edns65001_mac_missing_or_invalid')
  end
  return DNSAction.None
end

-- =============================================================================
-- Phase 2 — 设备类型判断（配合 LuaRule 在 dnsdist.conf 中使用）
-- =============================================================================
-- isClean / isNoFilter 通过 dq:getTag('mac') 读取 observeMacOption65001 设置
-- 的 tag，然后查 g_clean_macs 判断设备类型。
--
-- 无 EDNS 65001 时 mac tag 为空字符串：
--   - isClean 返回 false（没有 MAC 无法确认是 Clean 设备）
--   - isNoFilter 返回 true（安全默认：视为免过滤设备）
-- =============================================================================

-- isClean(dq): 是否在 mac-clean.txt 中（需过滤设备）
-- 返回 true 表示该设备走 blacklist → self_doh 链路
function isClean(dq)
  local hex = dq:getTag('mac')
  if hex == '' then return false end
  return g_clean_macs[hex] == true
end

-- isNoFilter(dq): 是否为免过滤设备（不在 clean 列表中 或 无 MAC）
-- 无 MAC 标记的设备也视为免过滤（安全默认），走 self_no_filter → cn_doh
function isNoFilter(dq)
  local hex = dq:getTag('mac')
  if hex == '' then return true end
  return not g_clean_macs[hex]
end
