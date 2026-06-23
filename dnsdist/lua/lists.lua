-- =============================================================================
-- lists.lua — 域名列表加载工具
-- =============================================================================
-- 将纯文本域名列表（每行一个域名）加载为 SuffixMatchNode，用于 dnsdist 的
-- SuffixMatchNodeRule 快速匹配。支持 # 注释行，自动去掉尾部点。
--
-- 在 dnsdist.conf 中用于加载：
--   block-nxdomain.txt  → NXDOMAIN 阻断列表
--   block-zero-ip.txt   → 0.0.0.0/:: 响应用于 SNI 阻断
--   allowlist.txt       → 豁免列表（绕过 blocklist 直达上游）
--   cn.txt              → 国内域名列表（用于托底分裂路由）
-- =============================================================================

-- loadDomainList(path): 加载域名列表文件到 SuffixMatchNode
--
-- @param path  string  文件路径
-- @return     SuffixMatchNode|nil  成功返回节点，文件无法打开返回 nil
-- @return     integer              加载的域名数量
--
-- 文件格式：
--   - 每行一个域名，可以有尾部点（自动去除）
--   - # 开头的行为注释
--   - 空行和首尾空白自动忽略
function loadDomainList(path)
  local f = io.open(path, 'r')
  if f == nil then
    warnlog('lists: cannot open ' .. path)
    return nil
  end

  local node = newSuffixMatchNode()
  local count = 0
  for line in f:lines() do
    -- 去除注释和首尾空白
    line = line:match('^[^#]*')
    line = line:match('^%s*(.-)%s*$')
    if line ~= '' then
      -- 去除尾部点
      line = line:gsub('%.$', '')
      node:add(newDNSName(line))
      count = count + 1
    end
  end
  f:close()
  infolog('lists: loaded ' .. count .. ' domains from ' .. path)
  return node, count
end
