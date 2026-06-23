---@meta

---@class ComboAddress
local ComboAddress = {}

---@param addr string
---@param port? integer
---@return ComboAddress
function ComboAddress.new(addr, port) end

---@return string
function ComboAddress:toString() end

---@return string
function ComboAddress:toStringWithPort() end

---@return boolean
function ComboAddress:isIPv4() end

---@return boolean
function ComboAddress:isIPv6() end

---@return boolean
function ComboAddress:isLoopback() end

---@return integer
function ComboAddress:hash() end
