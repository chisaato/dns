---@meta

---@class DNSAction
local DNSAction = {}

---@class DNSResponseAction
local DNSResponseAction = {}

---@param addrs string|string[]|ComboAddress|ComboAddress[]
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofAction(addrs, params) end

---@param cname string
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofCNAMEAction(cname, params) end

---@param data string|string[]
---@param params? {typeForAny?: integer, ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofRawAction(data, params) end

---@param params LuaArray<SVCRecordParameters>
---@param responseParams? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofSVCAction(params, responseParams) end

---@param response string
---@param len integer
---@return DNSAction
function SpoofPacketAction(response, len) end

---@param rcode integer
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function RCodeAction(rcode, params) end

---@param rcode integer
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function ERCodeAction(rcode, params) end

---@param v4Netmask string
---@param v6Netmask? string
---@return DNSAction
function SetECSAction(v4Netmask, v6Netmask) end

---@param max integer
---@return DNSResponseAction
function SetMaxReturnedTTLAction(max) end

---@param max integer
---@return DNSResponseAction
function SetMaxReturnedTTLResponseAction(max) end

---@param min integer
---@param max integer
---@param types? LuaArray<integer>
---@return DNSResponseAction
function LimitTTLResponseAction(min, max, types) end

---@param min integer
---@return DNSResponseAction
function SetMinTTLResponseAction(min) end

---@param max integer
---@return DNSResponseAction
function SetMaxTTLResponseAction(max) end

---@param percentage integer
---@return DNSResponseAction
function SetReducedTTLResponseAction(percentage) end

---@param types integer|integer[]
---@return DNSResponseAction
function ClearRecordTypesResponseAction(types) end

---@param remote string
---@param addECS? boolean
---@param localAddr? string
---@param addProxyProtocol? boolean
---@return DNSAction
function TeeAction(remote, addECS, localAddr, addProxyProtocol) end

---@param action DNSAction
---@return DNSAction
function ContinueAction(action) end

---@param status integer
---@param body string
---@param contentType? string
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function HTTPStatusAction(status, body, contentType, params) end

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
---@param params? {soaInAuthoritySection?: boolean, ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function NegativeAndSOAAction(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum, params) end

---@param values {[1]: integer, [2]: string}[]
---@return DNSAction
function SetProxyProtocolValuesAction(values) end

---@param func fun(dq: DNSQuestion): DNSAction
---@return DNSAction
function LuaAction(func) end

---@param func fun(dq: ffi_dnsquestion_t): integer
---@return DNSAction
function LuaFFIAction(func) end

---@param func fun(dr: DNSResponse): DNSResponseAction
---@return DNSResponseAction
function LuaResponseAction(func) end

---@param func fun(dr: ffi_dnsresponse_t): integer
---@return DNSResponseAction
function LuaFFIResponseAction(func) end
