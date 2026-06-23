---@meta

---@class DNSRule
local DNSRule = {}

---@param var luadnsrule_t
---@return DNSRule
function makeRule(var) end

---@param qtype integer|string
---@return DNSRule
function QTypeRule(qtype) end

---@param qclass integer
---@return DNSRule
function QClassRule(qclass) end

---@param qname string
---@return DNSRule
function QNameRule(qname) end

---@param names DNSNameSet
---@return DNSRule
function QNameSetRule(names) end

---@param names string|SuffixMatchNode|LuaArray<string>
---@param quiet? boolean
---@return DNSRule
function QNameSuffixRule(names, quiet) end

---@param names string|SuffixMatchNode|LuaArray<string>
---@param quiet? boolean
---@return DNSRule
function SuffixMatchNodeRule(names, quiet) end

---@param netmasks NetmaskGroup|string|LuaArray<string>
---@param src? boolean
---@param quiet? boolean
---@return DNSRule
function NetmaskGroupRule(netmasks, src, quiet) end

---@param rcode integer
---@return DNSRule
function RCodeRule(rcode) end

---@param rcode integer
---@return DNSRule
function ERCodeRule(rcode) end

---@param tag string
---@param value? string
---@return DNSRule
function TagRule(tag, value) end

---@param method string
---@return DNSRule
function HTTPMethodRule(method) end

---@param path string
---@return DNSRule
function HTTPPathRule(path) end

---@param host string
---@return DNSRule
function HTTPHostRule(host) end

---@param rules LuaArray<DNSRule>
---@return DNSRule
function AndRule(rules) end

---@param rules LuaArray<DNSRule>
---@return DNSRule
function OrRule(rules) end

---@param rule DNSRule
---@return DNSRule
function NotRule(rule) end

---@param func fun(dq: DNSQuestion): boolean
---@return DNSRule
function LuaRule(func) end

---@param func fun(dq: ffi_dnsquestion_t): boolean
---@return DNSRule
function LuaFFIRule(func) end

---@return TimedIPSetRule
function TimedIPSetRule() end
