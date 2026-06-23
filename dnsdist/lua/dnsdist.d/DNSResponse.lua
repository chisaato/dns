---@meta

---@class DNSResponse : DNSQuestion
local DNSResponse = {}

---@param editFunc fun(section: integer, qclass: integer, qtype: integer, ttl: integer): integer
function DNSResponse:editTTLs(editFunc) end

---@return DownstreamState|nil
function DNSResponse:getSelectedBackend() end

---@return boolean
function DNSResponse:getStaleCacheHit() end

---@return integer
function DNSResponse:getRestartCount() end

---@return boolean
function DNSResponse:restart() end
