---@meta

-- ============================================================================
-- dnsdist Lua API Type Definitions
-- For use with sumneko/lua-language-server (LuaCATS annotations)
-- ============================================================================

---@alias luadnsrule_t string|DNSName|DNSRule|SuffixMatchNode|LuaArray<string>|LuaArray<DNSName>
---@alias luaruleparams_t table<string, any>?
---@alias LuaArray<T> {[integer]: T}
