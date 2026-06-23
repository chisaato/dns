---@meta

---@class ServerPool
local ServerPool = {}

---@param cache PacketCache
function ServerPool:setCache(cache) end

---@return PacketCache
function ServerPool:getCache() end

---@param addr string
function setLocal(addr) end

---@param addr string
function addLocal(addr) end

---@param acl LuaArray<string>
function setACL(acl) end

---@param url  string
---@param pool string
function addUpstream(url, pool) end

---@param name string
---@return ServerPool
function getPool(name) end
---@param name string
---@return LuaArray<Server>
function getPoolServers(name) end

---@param path string
function dofile(path) end

---@param path string
function loadDevices(path) end

---@param params ServerParams
---@return DownstreamState
function addServer(params) end

---@param policy ServerPolicy
---@param pool?  string
function setServerPolicy(policy, pool) end

---@return ServerPolicy
function getServerPolicy() end

---@param policy ServerPolicy
---@param pool   string
function setPoolServerPolicy(policy, pool) end

---@param params ServerParams
---@return DownstreamState
function newServer(params) end

---@param rule    luadnsrule_t
---@param action  DNSAction
---@param params? luaruleparams_t
function addAction(rule, action, params) end

---@param rule    luadnsrule_t
---@param action  DNSResponseAction
---@param params? luaruleparams_t
function addResponseAction(rule, action, params) end

---@param params? { showUUIDs?: boolean, truncateRuleWidth?: integer }
function showRules(params) end

---@param params? { showUUIDs?: boolean, truncateRuleWidth?: integer }
function showResponseRules(params) end

---@param ruleID integer | string
function rmRule(ruleID) end

---@param ruleID integer | string
function rmResponseRule(ruleID) end

function mvRuleToTop() end

function mvResponseRuleToTop() end

---@param from integer
---@param dest integer
function mvRule(from, dest) end

---@param from integer
---@param dest integer
function mvResponseRule(from, dest) end

function clearRules() end

function clearResponseRules() end

---@param top? integer
---@return LuaArray<RuleAction>
function getTopRules(top) end

---@param top? integer
---@return LuaArray<ResponseRuleAction>
function getTopResponseRules(top) end

---@param num integer
---@return RuleAction | nil
function getRule(num) end

---@param num integer
---@return ResponseRuleAction | nil
function getResponseRule(num) end

---@param rule    luadnsrule_t
---@param action  DNSAction
---@param params? luaruleparams_t
---@return RuleAction
function newRuleAction(rule, action, params) end

---@param rules LuaArray<RuleAction>
function setRules(rules) end

---@param rule    DNSRule
---@param times?  integer
---@param suffix? string
function benchRule(rule, times, suffix) end

---@param msg string
function infolog(msg) end

---@param msg string
function warnlog(msg) end

---@param msg string
function errlog(msg) end

---@param msg string
function vinfolog(msg) end

---@return SuffixMatchNode
function newSuffixMatchNode() end

---@param name string
---@return DNSName
function newDNSName(name) end

---@return NetmaskGroup
function newNetmaskGroup() end

---@return string
function getUniqueID() end

---@param num integer
function setNumWorkers(num) end

---@return integer
function getNumWorkers() end

---@param maxEntries int
---@param params     PacketCacheParams
function newPacketCache(maxEntries, params) end

---@param pool  string
---@param cache PacketCache
function setPoolCache(pool, cache) end

---@class PersistentCacheConfig
---@field directory?       string  # Cache directory path (empty = disabled)
---@field saveInterval?    integer # Periodic save interval in seconds (0 = shutdown only)
---@field minDirtyEntries? integer # Minimum dirty entries before saving

---@param config? PersistentCacheConfig
function setPersistentCacheConfig(config) end

---@param fname string
---@return boolean
function PacketCache:save(fname) end

---@param fname string
---@return boolean
function PacketCache:load(fname) end

---@return boolean
function PacketCache:isDirty() end

-- ============================================================================
-- Custom functions (defined in lua/*.lua)
-- ============================================================================

---@param dq DNSQuestion
---@return boolean
function isClean(dq) end

---@param dq DNSQuestion
---@return boolean
function isNoFilter(dq) end

---@param dq DNSQuestion
---@return string
function getMacReadable(dq) end

---@param dq DNSQuestion
---@return string
function getDeviceType(dq) end

---@param qtype integer
---@return string
function qtypeStr(qtype) end

---@param msg  string
---@param pool string
---@return DNSAction
function logPoolHit(msg, pool) end

---@param msg   string
---@param rcode integer
---@return DNSAction
function logRcodeHit(msg, rcode) end

---@param msg string
---@return DNSAction
function logSpoofHit(msg) end

---@param msg       string
---@param routeFunc fun(dq: DNSQuestion): string
---@return DNSAction
function logRouteHit(msg, routeFunc) end

---@param tag    string
---@param data   LuaArray<{ [1]: string, [2]: any }>
---@param level? string
function logJson(tag, data, level) end

---@param dq DNSQuestion
---@return string
function routeSelfDohOrFallback(dq) end

---@param dq DNSQuestion
---@return string
function routeNoFilterOrFallback(dq) end

-- ============================================================================
-- Custom C++ bindings (patched into dnsdist binary)
-- ============================================================================

---@param domain string
---@param urls   string | LuaArray<string>
---@return LuaArray<string> | nil
function resolveViaDoH(domain, urls) end

---@param domain string
---@param urls   string | LuaArray<string>
---@return string | nil
function resolveViaDoHFirst(domain, urls) end
