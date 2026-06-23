---@meta

-- ============================================================================
-- dnsdist Lua API Type Definitions
-- Generated from PowerDNS/dnsdist source code (v2.1.x)
-- For use with sumneko/lua-language-server (LuaCATS annotations)
-- ============================================================================

-- ============================================================================
-- Forward declarations
-- ============================================================================
---@class DNSQuestion
---@class DNSResponse
---@class DNSRule
---@class DNSAction
---@class DNSResponseAction
---@class ComboAddress
---@class Netmask
---@class NetmaskGroup
---@class DNSName
---@class DNSNameSet
---@class SuffixMatchNode
---@class DNSHeader
---@class PacketCache
---@class ServerPool
---@class DownstreamState
---@class ClientState
---@class DynBlockRulesGroup
---@class DynBlock
---@class StatNode
---@class RemoteLogAction
---@class RemoteLogResponseAction

---@alias luadnsrule_t string|DNSName|DNSRule|SuffixMatchNode|LuaArray<string>|LuaArray<DNSName>
---@alias luaruleparams_t table<string, any>?
---@alias LuaArray<T> {[integer]: T}  -- 1-indexed array as used by LuaWrapper

-- ============================================================================
-- DNSQuestion / DNSResponse - Core query/response objects
-- ============================================================================

---@class DNSQuestion
---@field localaddr ComboAddress  # Local (destination) address
---@field qname DNSName            # Query domain name
---@field qtype integer            # Query type (e.g. QType.A = 1)
---@field qclass integer           # Query class (typically QClass.IN = 1)
---@field rcode integer            # Response code
---@field remoteaddr ComboAddress  # Remote (source) address
---@field dh dnsheader             # DNS header (mutable)
---@field len integer              # Packet length
---@field opcode integer           # DNS opcode
---@field tcp boolean              # Whether query came over TCP
---@field skipCache boolean        # Skip packet cache for this query
---@field pool string              # Server pool name
---@field useECS boolean           # Use EDNS Client Subnet
---@field ecsOverride boolean      # Override existing ECS
---@field ecsPrefixLength integer  # ECS prefix length
---@field tempFailureTTL integer|nil  # TTL for temporary failures
---@field deviceID string          # Device ID (protobuf)
---@field deviceName string        # Device name (protobuf)
---@field requestorID string       # Requestor ID (protobuf)
local DNSQuestion = {}

--- Get DNSSEC OK bit from EDNS
---@return boolean
function DNSQuestion:getDO() end

--- Get raw packet content as string
---@return string
function DNSQuestion:getContent() end

--- Set raw packet content from string
---@param raw string
function DNSQuestion:setContent(raw) end

--- Get EDNS options from the query
---@return LuaArray<EDNSOptionValues>
function DNSQuestion:getEDNSOptions() end

--- Remove an EDNS option by code
---@param code integer
function DNSQuestion:removeEDNSOption(code) end

--- Set an EDNS option
---@param code integer
---@param data string
function DNSQuestion:setEDNSOption(code, data) end

--- Get DNS header as a copy
---@return dnsheader
function DNSQuestion:getHeader() end

--- Set DNS header
---@param header dnsheader
function DNSQuestion:setHeader(header) end

--- Get trailing data after the DNS message
---@return string
function DNSQuestion:getTrailingData() end

--- Set trailing data after the DNS message
---@param tail string
---@return boolean success
function DNSQuestion:setTrailingData(tail) end

--- Get TLS Server Name Indication
---@return string
function DNSQuestion:getServerNameIndication() end

--- Get incoming network interface name
---@return string
function DNSQuestion:getIncomingInterface() end

--- Get protocol string (e.g. "DoUDP", "DoTCP", "DoH")
---@return string
function DNSQuestion:getProtocol() end

--- Get query timestamp
---@return timespec
function DNSQuestion:getQueryTime() end

--- Get elapsed time in microseconds
---@return number
function DNSQuestion:getElapsedUs() end

--- Send SNMP trap (requires net-snmp)
---@param reason? string
function DNSQuestion:sendTrap(reason) end

--- Set a tag on this query
---@param label string
---@param value string
function DNSQuestion:setTag(label, value) end

--- Unset a tag
---@param label string
function DNSQuestion:unsetTag(label) end

--- Set multiple tags at once
---@param tags table<string, string>
function DNSQuestion:setTagArray(tags) end

--- Get a tag value (returns empty string if not set)
---@param label string
---@return string
function DNSQuestion:getTag(label) end

--- Get all tags as a table
---@return table<string, string>
function DNSQuestion:getTagArray() end

--- Set protobuf meta key
---@param key string
---@param values LuaArray<integer|string>
function DNSQuestion:setMetaKey(key, values) end

--- Set Extended DNS Error
---@param infoCode integer
---@param extraText? string
---@param clearExisting? boolean
function DNSQuestion:setExtendedDNSError(infoCode, extraText, clearExisting) end

--- Suspend this query for async processing
---@param asyncID integer
---@param queryID integer
---@param timeoutMs integer
---@return boolean success
function DNSQuestion:suspend(asyncID, queryID, timeoutMs) end

--- Spoof response with IP addresses or RData strings
---@param response ComboAddress|string|LuaArray<ComboAddress>|LuaArray<string>
---@param typeForAny? integer
function DNSQuestion:spoof(response, typeForAny) end

--- Change the query name
---@param newName DNSName
---@return boolean success
function DNSQuestion:changeName(newName) end

--- Make this query restartable
---@return boolean
function DNSQuestion:setRestartable() end

--- Get trace ID for distributed tracing
---@return string|nil
function DNSQuestion:getTraceID() end

--- Get span ID for distributed tracing
---@return string|nil
function DNSQuestion:getSpanID() end

--- Get HTTP path (DoH/DoH3 only)
---@return string
function DNSQuestion:getHTTPPath() end

--- Get HTTP query string (DoH/DoH3 only)
---@return string
function DNSQuestion:getHTTPQueryString() end

--- Get HTTP host header (DoH/DoH3 only)
---@return string
function DNSQuestion:getHTTPHost() end

--- Get HTTP scheme (DoH/DoH3 only)
---@return string
function DNSQuestion:getHTTPScheme() end

--- Get HTTP headers (DoH/DoH3 only)
---@return table<string, string>
function DNSQuestion:getHTTPHeaders() end

--- Set HTTP response (DoH/DoH3 only)
---@param statusCode integer
---@param body string
---@param contentType? string
function DNSQuestion:setHTTPResponse(statusCode, body, contentType) end

--- Set negative response with SOA
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

---@class DNSResponse : DNSQuestion
local DNSResponse = {}

--- Edit TTLs in the response
---@param editFunc fun(section: integer, qclass: integer, qtype: integer, ttl: integer): integer
function DNSResponse:editTTLs(editFunc) end

--- Get selected downstream server
---@return DownstreamState|nil
function DNSResponse:getSelectedBackend() end

--- Check if this is a stale cache hit
---@return boolean
function DNSResponse:getStaleCacheHit() end

--- Get restart count
---@return integer
function DNSResponse:getRestartCount() end

--- Restart the query from the beginning
---@return boolean
function DNSResponse:restart() end

-- ============================================================================
-- DNSHeader - DNS packet header
-- ============================================================================

---@class dnsheader
---@field id integer        # Transaction ID
---@field qr boolean        # Query/Response flag
---@field opcode integer    # Opcode
---@field aa boolean        # Authoritative Answer
---@field tc boolean        # Truncation
---@field rd boolean        # Recursion Desired
---@field ra boolean        # Recursion Available
---@field z boolean         # Reserved
---@field ad boolean        # Authenticated Data
---@field cd boolean        # Checking Disabled
---@field rcode integer     # Response Code
---@field qdcount integer   # Question Count
---@field ancount integer   # Answer Count
---@field nscount integer   # Authority Count
---@field arcount integer   # Additional Count
local dnsheader = {}

-- ============================================================================
-- ComboAddress - IP address wrapper
-- ============================================================================

---@class ComboAddress
local ComboAddress = {}

--- Create a new ComboAddress
---@param addr string  # IP address string (e.g. "127.0.0.1", "::1")
---@param port? integer # Port number (default 0)
---@return ComboAddress
function ComboAddress.new(addr, port) end

--- Get string representation
---@return string
function ComboAddress:toString() end

--- Get address without port
---@return string
function ComboAddress:toStringWithPort() end

--- Check if address is IPv4
---@return boolean
function ComboAddress:isIPv4() end

--- Check if address is IPv6
---@return boolean
function ComboAddress:isIPv6() end

--- Check if address is loopback
---@return boolean
function ComboAddress:isLoopback() end

--- Get hash value
---@return integer
function ComboAddress:hash() end

-- ============================================================================
-- Netmask - Network mask
-- ============================================================================

---@class Netmask
local Netmask = {}

--- Create a new Netmask
---@param mask string  # Network mask (e.g. "192.168.1.0/24", "10.0.0.1")
---@return Netmask
function Netmask.new(mask) end

--- Check if address matches this netmask
---@param addr ComboAddress
---@return boolean
function Netmask:match(addr) end

--- Get string representation
---@return string
function Netmask:toString() end

--- Check if this netmask contains another
---@param other Netmask
---@return boolean
function Netmask:contains(other) end

--- Get network address
---@return ComboAddress
function Netmask:getNetwork() end

--- Get mask length
---@return integer
function Netmask:getMaskLen() end

-- ============================================================================
-- NetmaskGroup - Collection of network masks
-- ============================================================================

---@class NetmaskGroup
local NetmaskGroup = {}

--- Create a new NetmaskGroup
---@return NetmaskGroup
function NetmaskGroup.new() end

--- Add a mask to the group
---@param mask string|Netmask
function NetmaskGroup:addMask(mask) end

--- Check if address matches any mask
---@param addr ComboAddress
---@return boolean
function NetmaskGroup:match(addr) end

--- Check if the group is empty
---@return boolean
function NetmaskGroup:empty() end

-- ============================================================================
-- DNSName - Domain name
-- ============================================================================

---@class DNSName
local DNSName = {}

--- Create a new DNSName
---@param name string  # Domain name (e.g. "example.com.")
---@return DNSName
function DNSName.new(name) end

--- Check if name is empty
---@return boolean
function DNSName:empty() end

--- Get string representation
---@return string
function DNSName:toString() end

--- Check if name is root
---@return boolean
function DNSName:isRoot() end

--- Check if name is a wildcard
---@return boolean
function DNSName:isWildcard() end

--- Count labels
---@return integer
function DNSName:countLabels() end

--- Concatenate names
---@param other DNSName
---@return DNSName
function DNSName.__concat(other) end

--- Check equality
---@param other DNSName
---@return boolean
function DNSName.__eq(other) end

--- Check if less than
---@param other DNSName
---@return boolean
function DNSName.__lt(other) end

--- Check if less or equal
---@param other DNSName
---@return boolean
function DNSName.__le(other) end

-- ============================================================================
-- DNSNameSet - Set of domain names
-- ============================================================================

---@class DNSNameSet
local DNSNameSet = {}

--- Create a new DNSNameSet
---@return DNSNameSet
function DNSNameSet.new() end

--- Add a name to the set
---@param name DNSName
function DNSNameSet:add(name) end

--- Remove a name from the set
---@param name DNSName
function DNSNameSet:remove(name) end

--- Check if name exists in set
---@param name DNSName
---@return boolean
function DNSNameSet:check(name) end

--- Check if set is empty
---@return boolean
function DNSNameSet:empty() end

--- Get size of set
---@return integer
function DNSNameSet:size() end

-- ============================================================================
-- SuffixMatchNode - Efficient suffix matching
-- ============================================================================

---@class SuffixMatchNode
local SuffixMatchNode = {}

--- Create a new SuffixMatchNode
---@return SuffixMatchNode
function SuffixMatchNode.new() end

--- Add a domain to the node
---@param name DNSName
function SuffixMatchNode:add(name) end

--- Check if a domain matches any added suffix
---@param name DNSName
---@return boolean
function SuffixMatchNode:check(name) end

--- Check if node is empty
---@return boolean
function SuffixMatchNode:empty() end

-- ============================================================================
-- EDNSOptionValues
-- ============================================================================

---@class EDNSOptionValues
---@field values LuaArray<string>  # Option values
local EDNSOptionValues = {}

-- ============================================================================
-- Global Functions - Configuration
-- ============================================================================

--- Add a server to the default pool
---@param params ServerParams
---@return DownstreamState
function addServer(params) end

--- Set the server policy
---@param policy ServerPolicy
---@param pool? string  # Pool name (default: default pool)
function setServerPolicy(policy, pool) end

--- Get the current server policy
---@return ServerPolicy
function getServerPolicy() end

--- Set the server pool policy
---@param policy ServerPolicy
---@param pool string
function setPoolServerPolicy(policy, pool) end

--- Add a server to a specific pool
---@param pool string
---@param params ServerParams
---@return DownstreamState
function newServer(params) end  -- Note: also named newServer in some contexts

-- ============================================================================
-- Global Functions - Rules Management
-- ============================================================================

--- Add a query rule with action
---@param rule luadnsrule_t
---@param action DNSAction
---@param params? luaruleparams_t
function addAction(rule, action, params) end

--- Add a response rule with action
---@param rule luadnsrule_t
---@param action DNSResponseAction
---@param params? luaruleparams_t
function addResponseAction(rule, action, params) end

--- Show all query rules
---@param params? {showUUIDs?: boolean, truncateRuleWidth?: integer}
function showRules(params) end

--- Show all response rules
---@param params? {showUUIDs?: boolean, truncateRuleWidth?: integer}
function showResponseRules(params) end

--- Remove a rule by index or UUID/name
---@param ruleID integer|string
function rmRule(ruleID) end

--- Remove a response rule by index or UUID/name
---@param ruleID integer|string
function rmResponseRule(ruleID) end

--- Move a rule to the top
function mvRuleToTop() end

--- Move a response rule to the top
function mvResponseRuleToTop() end

--- Move a rule to a new position
---@param from integer
---@param dest integer
function mvRule(from, dest) end

--- Move a response rule to a new position
---@param from integer
---@param dest integer
function mvResponseRule(from, dest) end

--- Clear all rules
function clearRules() end

--- Clear all response rules
function clearResponseRules() end

--- Get top N rules by match count
---@param top? integer
---@return LuaArray<RuleAction>
function getTopRules(top) end

--- Get top N response rules by match count
---@param top? integer
---@return LuaArray<ResponseRuleAction>
function getTopResponseRules(top) end

--- Get a specific rule by index
---@param num integer
---@return RuleAction|nil
function getRule(num) end

--- Get a specific response rule by index
---@param num integer
---@return ResponseRuleAction|nil
function getResponseRule(num) end

--- Create a rule+action pair (for use with setRules)
---@param rule luadnsrule_t
---@param action DNSAction
---@param params? luaruleparams_t
---@return RuleAction
function newRuleAction(rule, action, params) end

--- Set all rules at once (replaces existing)
---@param rules LuaArray<RuleAction>
function setRules(rules) end

--- Benchmark a rule
---@param rule DNSRule
---@param times? integer
---@param suffix? string
function benchRule(rule, times, suffix) end

-- ============================================================================
-- Global Functions - Selectors (Rules)
-- ============================================================================

--- Create a rule from a domain list, netmask, or rule object
---@param var luadnsrule_t
---@return DNSRule
function makeRule(var) end

--- Rule matching QType
---@param qtype integer|string
---@return DNSRule
function QTypeRule(qtype) end

--- Rule matching QClass
---@param qclass integer
---@return DNSRule
function QClassRule(qclass) end

--- Rule matching exact QName
---@param qname string
---@return DNSRule
function QNameRule(qname) end

--- Rule matching a set of QNames
---@param names DNSNameSet
---@return DNSRule
function QNameSetRule(names) end

--- Rule matching QName suffix (string, array, or SuffixMatchNode)
---@param names string|SuffixMatchNode|LuaArray<string>
---@param quiet? boolean
---@return DNSRule
function QNameSuffixRule(names, quiet) end

--- Alias for QNameSuffixRule
---@param names string|SuffixMatchNode|LuaArray<string>
---@param quiet? boolean
---@return DNSRule
function SuffixMatchNodeRule(names, quiet) end

--- Rule matching NetmaskGroup
---@param netmasks NetmaskGroup|string|LuaArray<string>
---@param src? boolean      # Match source (default true)
---@param quiet? boolean    # Suppress warnings
---@return DNSRule
function NetmaskGroupRule(netmasks, src, quiet) end

--- Rule matching RCode
---@param rcode integer
---@return DNSRule
function RCodeRule(rcode) end

--- Rule matching Extended RCode
---@param rcode integer
---@return DNSRule
function ERCodeRule(rcode) end

--- Rule matching on a tag
---@param tag string
---@param value? string  # If provided, matches tag=value; otherwise matches tag exists
---@return DNSRule
function TagRule(tag, value) end

--- Rule matching HTTP method
---@param method string
---@return DNSRule
function HTTPMethodRule(method) end

--- Rule matching HTTP path
---@param path string
---@return DNSRule
function HTTPPathRule(path) end

--- Rule matching HTTP host
---@param host string
---@return DNSRule
function HTTPHostRule(host) end

--- AND rule (all sub-rules must match)
---@param rules LuaArray<DNSRule>
---@return DNSRule
function AndRule(rules) end

--- OR rule (at least one sub-rule must match)
---@param rules LuaArray<DNSRule>
---@return DNSRule
function OrRule(rules) end

--- NOT rule (invert match)
---@param rule DNSRule
---@return DNSRule
function NotRule(rule) end

--- Lua selector function rule
---@param func fun(dq: DNSQuestion): boolean
---@return DNSRule
function LuaRule(func) end

--- FFI-based Lua selector rule
---@param func fun(dq: ffi_dnsquestion_t): boolean
---@return DNSRule
function LuaFFIRule(func) end

--- Timed IP Set Rule
---@return TimedIPSetRule
function TimedIPSetRule() end

-- ============================================================================
-- Global Functions - Actions
-- ============================================================================

--- Spoof response with IP addresses
---@param addrs string|string[]|ComboAddress|ComboAddress[]
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofAction(addrs, params) end

--- Spoof response with CNAME
---@param cname string
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofCNAMEAction(cname, params) end

--- Spoof response with raw data
---@param data string|string[]
---@param params? {typeForAny?: integer, ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofRawAction(data, params) end

--- Spoof response with SVCB record
---@param params LuaArray<SVCRecordParameters>
---@param responseParams? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function SpoofSVCAction(params, responseParams) end

--- Spoof response with entire packet
---@param response string
---@param len integer
---@return DNSAction
function SpoofPacketAction(response, len) end

--- Set RCode
---@param rcode integer
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function RCodeAction(rcode, params) end

--- Set Extended RCode
---@param rcode integer
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function ERCodeAction(rcode, params) end

--- Set ECS
---@param v4Netmask string
---@param v6Netmask? string
---@return DNSAction
function SetECSAction(v4Netmask, v6Netmask) end

--- Set Max Returned TTL
---@param max integer
---@return DNSResponseAction
function SetMaxReturnedTTLAction(max) end

--- Set Max Returned TTL (response)
---@param max integer
---@return DNSResponseAction
function SetMaxReturnedTTLResponseAction(max) end

--- Limit TTL in response
---@param min integer
---@param max integer
---@param types? LuaArray<integer>
---@return DNSResponseAction
function LimitTTLResponseAction(min, max, types) end

--- Set minimum TTL in response
---@param min integer
---@return DNSResponseAction
function SetMinTTLResponseAction(min) end

--- Set maximum TTL in response
---@param max integer
---@return DNSResponseAction
function SetMaxTTLResponseAction(max) end

--- Reduce TTL by percentage
---@param percentage integer  # 0-100
---@return DNSResponseAction
function SetReducedTTLResponseAction(percentage) end

--- Clear specific record types from response
---@param types integer|integer[]
---@return DNSResponseAction
function ClearRecordTypesResponseAction(types) end

--- Tee action (mirror to another server)
---@param remote string
---@param addECS? boolean
---@param localAddr? string
---@param addProxyProtocol? boolean
---@return DNSAction
function TeeAction(remote, addECS, localAddr, addProxyProtocol) end

--- Continue with next rule after this action
---@param action DNSAction
---@return DNSAction
function ContinueAction(action) end

--- HTTP Status response action (DoH only)
---@param status integer
---@param body string
---@param contentType? string
---@param params? {ttl?: integer, aa?: boolean, ad?: boolean, ra?: boolean}
---@return DNSAction
function HTTPStatusAction(status, body, contentType, params) end

--- Negative and SOA action
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

--- Set Proxy Protocol Values
---@param values {[1]: integer, [2]: string}[]  # Array of {type, value} pairs
---@return DNSAction
function SetProxyProtocolValuesAction(values) end

--- Lua custom action
---@param func fun(dq: DNSQuestion): DNSAction
---@return DNSAction
function LuaAction(func) end

--- Lua FFI custom action
---@param func fun(dq: ffi_dnsquestion_t): integer
---@return DNSAction
function LuaFFIAction(func) end

--- Lua custom response action
---@param func fun(dr: DNSResponse): DNSResponseAction
---@return DNSResponseAction
function LuaResponseAction(func) end

--- Lua FFI custom response action
---@param func fun(dr: ffi_dnsresponse_t): integer
---@return DNSResponseAction
function LuaFFIResponseAction(func) end

-- ============================================================================
-- Global Functions - Logging
-- ============================================================================

--- Log informational message
---@param msg string
function infolog(msg) end

--- Log warning message
---@param msg string
function warnlog(msg) end

--- Log error message
---@param msg string
function errlog(msg) end

--- Log verbose message
---@param msg string
function vinfolog(msg) end

-- ============================================================================
-- Global Functions - Utilities
-- ============================================================================

--- Create a new SuffixMatchNode
---@return SuffixMatchNode
function newSuffixMatchNode() end

--- Create a new DNSName
---@param name string
---@return DNSName
function newDNSName(name) end

--- Create a new NetmaskGroup
---@return NetmaskGroup
function newNetmaskGroup() end

--- Get unique identifier
---@return string
function getUniqueID() end

--- Set the number of worker threads
---@param num integer
function setNumWorkers(num) end

--- Get the number of worker threads
---@return integer
function getNumWorkers() end

-- ============================================================================
-- Global Functions - Packet Cache
-- ============================================================================

--- Add a packet cache
---@param params PacketCacheParams
function newPacketCache(params) end

--- Set the packet cache for a pool
---@param pool string
---@param cache PacketCache
function setPoolCache(pool, cache) end

-- ============================================================================
-- Constants - QType
-- ============================================================================

---@enum QType
QType = {
    A      = 1,
    NS     = 2,
    CNAME  = 5,
    SOA    = 6,
    PTR    = 12,
    MX     = 15,
    TXT    = 16,
    AAAA   = 28,
    SRV    = 33,
    SSHFP  = 44,
    HTTPS  = 65,
    SVCB   = 64,
    OPT    = 41,
    DS     = 43,
    RRSIG  = 46,
    NSEC   = 47,
    DNSKEY = 48,
    TLSA   = 52,
    CAA    = 257,
    ANY    = 255,
    -- Add more as needed
}

-- ============================================================================
-- Constants - QClass
-- ============================================================================

---@enum QClass
QClass = {
    IN   = 1,
    CH   = 3,
    HS   = 4,
    ANY  = 255,
}

-- ============================================================================
-- Constants - DNSAction
-- ============================================================================

---@enum DNSActionKind
DNSAction = {
    None      = 0,
    Allow     = 1,
    Drop      = 2,
    NXDOMAIN  = 3,
    NODATA    = 4,
    Refused   = 5,
    Spoof     = 6,
    Modify    = 7,
    Pipe      = 8,
    QueryLocalAction = 9,
    Forward   = 10,
    Truncate  = 11,
    RateLimit = 12,
    SetEDNSOption = 13,
    SetTag    = 14,
    LimitTTL  = 15,
    MaskedIPSet = 16,
    SlowAnswer = 17,
    Eccentric = 18,
    FixUpCase = 19,
    ReturnSmallAnswer = 20,
    SetSkipCache = 21,
    ECSOverrideAction = 22,
    PoolAction = 23,
    TaggedCacheInsertAction = 24,
    CacheHitResponseAction = 25,
    RuleHitResponseAction = 26,
    SetDNSSECTTL = 27,
    SnapCacheResponseAction = 28,
    RestoreFlags = 29,
    Metric = 30,
}

-- ============================================================================
-- Constants - RCode
-- ============================================================================

---@enum RCode
RCode = {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp   = 4,
    Refused  = 5,
}

-- ============================================================================
-- Constants - DNS Header Flags (for dh field manipulation)
-- ============================================================================

-- DNS Opcodes
---@enum Opcode
Opcode = {
    Query     = 0,
    IQuery    = 1,
    Status    = 2,
    Notify    = 4,
    Update    = 5,
}

-- ============================================================================
-- Type stubs for parameter objects
-- ============================================================================

---@class ServerParams
---@field address string           # Server address (IP:port or DoH URL)
---@field pool? string|LuaArray<string>  # Server pool(s)
---@field qps? integer            # Max QPS (0 = unlimited)
---@field order? integer          # Server order
---@field weight? integer         # Server weight
---@field retries? integer        # Retries
---@field tcpConnectTimeout? integer  # TCP connect timeout (ms)
---@field tcpSendTimeout? integer    # TCP send timeout (ms)
---@field tcpRecvTimeout? integer    # TCP receive timeout (ms)
---@field doh? boolean            # Use DNS over HTTPS
---@field dohPath? string         # DoH path
---@field tls? string             # TLS mode ("dns", "openssl", "gnutls")
---@field subjectName? string     # TLS subject name
---@field caStore? string         # CA certificate store path
---@field ciphers? string         # TLS ciphers
---@field ciphers13? string       # TLS 1.3 ciphers
---@field certFile? string        # Client certificate file
---@field keyFile? string         # Client key file
---@field checkInterval? integer  # Health check interval (seconds)
---@field checkClass? integer     # Health check QClass
---@field checkType? integer      # Health check QType
---@field checkName? string       # Health check domain
---@field rise? integer           # Checks before marking up
---@field fall? integer           # Checks before marking down
---@field useClientSubnet? boolean  # Use ECS
---@field setCD? boolean          # Set checking disabled flag
---@field source? string          # Source address/port
---@field sourcePort? integer     # Source port
local ServerParams = {}

---@class SVCRecordParameters
---@field priority integer
---@field serviceName string
---@field target string
---@field alpn? LuaArray<string>
---@field noDefaultAlpn? boolean
---@field port? integer
---@field ipv4hint? LuaArray<string>
---@field ipv6hint? LuaArray<string>
---@field echconfig? string
---@field mandatory? LuaArray<string>
---@field dohpath? string
---@field ohttp? boolean
local SVCRecordParameters = {}

---@class PacketCacheParams
---@field maxSize integer           # Max cache entries
---@field maxTTL? integer           # Max TTL (default 86400)
---@field minTTL? integer           # Min TTL (default 0)
---@field maxNegativeTTL? integer   # Max TTL for negative (default 60)
---@field temporaryFailureTTL? integer  # TTL for SERVFAIL (default 60)
---@field staleTTL? integer         # TTL for stale entries (default 60)
---@field keepStaleData? boolean    # Keep stale data (default true)
---@field isCachingOnly? boolean    # Cache-only mode
---@field deforestTimeout? integer  # Don't cache for longer than this (seconds)
---@field cookieOnly? boolean       # Only cache with valid cookie
---@field shared? boolean           # Share cache between threads
---@field options? LuaArray<integer>  # Cache options (e.g. ECS)
---@field name? string              # Cache name
---@field doKeyCallback? boolean    # Do key callback
local PacketCacheParams = {}
