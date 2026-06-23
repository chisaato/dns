---@meta

---@class DNSQuestion
---@field localaddr ComboAddress
---@field qname DNSName
---@field qtype integer
---@field qclass integer
---@field rcode integer
---@field remoteaddr ComboAddress
---@field dh dnsheader
---@field len integer
---@field opcode integer
---@field tcp boolean
---@field skipCache boolean
---@field pool string
---@field useECS boolean
---@field ecsOverride boolean
---@field ecsPrefixLength integer
---@field tempFailureTTL integer|nil
---@field deviceID string
---@field deviceName string
---@field requestorID string
local DNSQuestion = {}

---@return boolean
function DNSQuestion:getDO() end

---@return string
function DNSQuestion:getContent() end

---@param raw string
function DNSQuestion:setContent(raw) end

---@return LuaArray<EDNSOptionValues>
function DNSQuestion:getEDNSOptions() end

---@param code integer
function DNSQuestion:removeEDNSOption(code) end

---@param code integer
---@param data string
function DNSQuestion:setEDNSOption(code, data) end

---@return dnsheader
function DNSQuestion:getHeader() end

---@param header dnsheader
function DNSQuestion:setHeader(header) end

---@return string
function DNSQuestion:getTrailingData() end

---@param tail string
---@return boolean
function DNSQuestion:setTrailingData(tail) end

---@return string
function DNSQuestion:getServerNameIndication() end

---@return string
function DNSQuestion:getIncomingInterface() end

---@return string
function DNSQuestion:getProtocol() end

---@return timespec
function DNSQuestion:getQueryTime() end

---@return number
function DNSQuestion:getElapsedUs() end

---@param reason? string
function DNSQuestion:sendTrap(reason) end

---@param label string
---@param value string
function DNSQuestion:setTag(label, value) end

---@param label string
function DNSQuestion:unsetTag(label) end

---@param tags table<string, string>
function DNSQuestion:setTagArray(tags) end

---@param label string
---@return string
function DNSQuestion:getTag(label) end

---@return table<string, string>
function DNSQuestion:getTagArray() end

---@param key string
---@param values LuaArray<integer|string>
function DNSQuestion:setMetaKey(key, values) end

---@param infoCode integer
---@param extraText? string
---@param clearExisting? boolean
function DNSQuestion:setExtendedDNSError(infoCode, extraText, clearExisting) end

---@param asyncID integer
---@param queryID integer
---@param timeoutMs integer
---@return boolean
function DNSQuestion:suspend(asyncID, queryID, timeoutMs) end

---@param response ComboAddress|string|LuaArray<ComboAddress>|LuaArray<string>
---@param typeForAny? integer
function DNSQuestion:spoof(response, typeForAny) end

---@param newName DNSName
---@return boolean
function DNSQuestion:changeName(newName) end

---@return boolean
function DNSQuestion:setRestartable() end

---@return string|nil
function DNSQuestion:getTraceID() end

---@return string|nil
function DNSQuestion:getSpanID() end

---@return string
function DNSQuestion:getHTTPPath() end

---@return string
function DNSQuestion:getHTTPQueryString() end

---@return string
function DNSQuestion:getHTTPHost() end

---@return string
function DNSQuestion:getHTTPScheme() end

---@return table<string, string>
function DNSQuestion:getHTTPHeaders() end

---@param statusCode integer
---@param body string
---@param contentType? string
function DNSQuestion:setHTTPResponse(statusCode, body, contentType) end

---@param nxd boolean
---@param zone string
---@param ttl integer
---@param mname string
---@param rname string
---@param serial integer
---@param refresh integer
---@param retry integer
---@param expire integer
---@param minimum integer
---@return boolean
function DNSQuestion:setNegativeAndAdditionalSOA(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum) end
