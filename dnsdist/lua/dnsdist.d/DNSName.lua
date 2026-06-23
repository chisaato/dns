---@meta

---@class DNSName
local DNSName = {}

---@param name string
---@return DNSName
function DNSName.new(name) end

---@return boolean
function DNSName:empty() end

---@return string
function DNSName:toString() end

---@return boolean
function DNSName:isRoot() end

---@return boolean
function DNSName:isWildcard() end

---@return integer
function DNSName:countLabels() end

---@param other DNSName
---@return DNSName
function DNSName.__concat(other) end

---@param other DNSName
---@return boolean
function DNSName.__eq(other) end

---@param other DNSName
---@return boolean
function DNSName.__lt(other) end

---@param other DNSName
---@return boolean
function DNSName.__le(other) end

---@class DNSNameSet
local DNSNameSet = {}

---@return DNSNameSet
function DNSNameSet.new() end

---@param name DNSName
function DNSNameSet:add(name) end

---@param name DNSName
function DNSNameSet:remove(name) end

---@param name DNSName
---@return boolean
function DNSNameSet:check(name) end

---@return boolean
function DNSNameSet:empty() end

---@return integer
function DNSNameSet:size() end

---@class SuffixMatchNode
local SuffixMatchNode = {}

---@return SuffixMatchNode
function SuffixMatchNode.new() end

---@param name DNSName
function SuffixMatchNode:add(name) end

---@param name DNSName
---@return boolean
function SuffixMatchNode:check(name) end

---@return boolean
function SuffixMatchNode:empty() end

---@class EDNSOptionValues
---@field values LuaArray<string>
local EDNSOptionValues = {}
