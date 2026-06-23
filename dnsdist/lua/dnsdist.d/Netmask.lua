---@meta

---@class Netmask
local Netmask = {}

---@param mask string
---@return Netmask
function Netmask.new(mask) end

---@param addr ComboAddress
---@return boolean
function Netmask:match(addr) end

---@return string
function Netmask:toString() end

---@param other Netmask
---@return boolean
function Netmask:contains(other) end

---@return ComboAddress
function Netmask:getNetwork() end

---@return integer
function Netmask:getMaskLen() end

---@class NetmaskGroup
local NetmaskGroup = {}

---@return NetmaskGroup
function NetmaskGroup.new() end

---@param mask string|Netmask
function NetmaskGroup:addMask(mask) end

---@param addr ComboAddress
---@return boolean
function NetmaskGroup:match(addr) end

---@return boolean
function NetmaskGroup:empty() end
