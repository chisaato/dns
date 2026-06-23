---@meta

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
}

---@enum QClass
QClass = {
    IN   = 1,
    CH   = 3,
    HS   = 4,
    ANY  = 255,
}

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

---@enum RCode
RCode = {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp   = 4,
    Refused  = 5,
}

---@enum Opcode
Opcode = {
    Query     = 0,
    IQuery    = 1,
    Status    = 2,
    Notify    = 4,
    Update    = 5,
}
