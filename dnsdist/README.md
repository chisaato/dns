# dnsdist

当前 dnsdist 是正式 DNS 入口，监听：

```text
0.0.0.0:1853
```

旧链路 `mosdns` / `AdGuardHome` / `dnsproxy` 均已停止，不再承载运行时解析。

## 版本

使用本地自构建镜像 `dnsdist-custom:2.1.0-rc1`（基于 `powerdns/dnsdist-21:2.1.0-rc1`）。

定制内容：

- **全特性编译**：YAML、Rust、quiche (DoH3)、eBPF、XSK、DNSCrypt、dnstap、LMDB
- **`dq:removeEDNSOption(code)` Lua 绑定**（补丁）：可在转发前剥离私有 EDNS option，解决上游 DoH 服务器 HTTP 502 拒绝问题
- **`resolveViaDoH()` / `resolveViaDoHFirst()` Lua 绑定**（补丁）：内建 DoH bootstrap 解析器，替代外部 dnsproxy
- **LLVM/Clang + LTO thin 编译**：体积优化、性能更好

选择 2.1.x 的原因：

- EDNS option API 在 2.1 起使用拷贝语义，避免 1.9 系裸指针视图风险。
- 后续可接入 YAML 配置、OpenTelemetry、Lua health-check callback 等能力。
- 不再维护 1.9.x 兼容路径。

## DoH Bootstrap 解析器

所有上游 DoH 服务器的域名解析通过内建的 `resolveViaDoHFirst()` 完成，而非系统 DNS 或外部 dnsproxy。

### 原理

```
dnsdist.conf 加载时
  ↓
resolveViaDoHFirst('doh.pub', {
    'https://223.5.5.5/dns-query',   ← 纯 IPv4 DoH 端点
    'https://1.12.12.12/dns-query',  ← 多端点随机 fallback
  })
  ↓
TCP → TLS → HTTP/1.1 POST /dns-query (application/dns-message)
  ↓
解析 DNS 响应 → 提取 A/AAAA 记录 → 返回纯 IP 字符串
  ↓
newServer({ address = ip .. ':443', subjectName = 'doh.pub', ... })
```

- 不依赖系统 DNS（无明文 UDP 53 查询）
- 支持多个 bootstrap 端点，随机顺序尝试，自动 fallback
- 双栈：同时查询 A（IPv4）和 AAAA（IPv6），IPv4 优先
- 仅在 `dnsdist.conf` 加载时执行一次；配合外部定时重启可获取最新 IP

### Lua API

```lua
-- 返回 IP 表（双栈全量）
local ips = resolveViaDoH('doh.pub', {
  'https://223.5.5.5/dns-query',
  'https://1.12.12.12/dns-query',
})

-- 返回第一个 IP（字符串，便捷版）
local ip = resolveViaDoHFirst('doh.pub', {
  'https://223.5.5.5/dns-query',
  'https://1.12.12.12/dns-query',
})

-- 兼容单个 URL
resolveViaDoHFirst('doh.pub', 'https://223.5.5.5/dns-query')
```

实际配置中的用法：

```lua
local BS = {'https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query'}

function dohServer(domain, pool, port, path, name)
  local ip = resolveViaDoHFirst(domain, BS)
  newServer({
    address = ip .. ':' .. (port or 443),
    name = name or domain,
    tls = 'openssl',
    subjectName = domain,
    dohPath = path or '/dns-query',
    pool = pool,
  })
end

dohServer('doh.pub', 'cn')
dohServer('dns.alidns.com', 'cn')
dohServer('lumine.misakacloud.dev', 'overseas', 8443, '/path/dns-query')
```

### v1.x → v2.x bootstrap 迁移

| 版本 | 方式 | 缺点 |
|------|------|------|
| v1.x | 硬编码 IP（如 `1.12.12.12:443`） | IP 变更需手动改配置 |
| v2.x | `resolveViaDoHFirst()` 内建 DoH bootstrap | 配置加载时自动解析最新 IP |

## 启动

```bash
docker compose up -d dnsdist
```

检查监听：

```bash
ss -lunpt | grep ':1853\\b'
docker compose ps dnsdist
```

## 规则链

```text
 1. MAC 观测 + 剥离 EDNS 65001
 2. [Clean MAC] allowlist 豁免 → self_doh               ← 白名单优先于黑名单
 3. [Clean MAC] blocklist nxdomain → NXDOMAIN
 4. [Clean MAC] blocklist zero-ip → 0.0.0.0 / ::
 5. [Clean MAC] 其余 → self_doh（带健康检查托底）
 6. [非 Clean MAC] → self_no_filter（带健康检查托底）
 7. HTTPS QTYPE 65 → NXDOMAIN
 8. 兜底 → cn_doh
```

## 上游 Pool（全加密）

| Pool | 用途 | 上游 | 协议 |
|------|------|------|------|
| self_doh | Clean 设备主上游（自建 AdGuard，带过滤） | seek.zerodream.net / rsv.1919810.cn | DoH ✅ |
| self_no_filter | 免过滤设备上游（自建无过滤） | seek.zerodream.net / rsv.1919810.cn (no-filter) | DoH ✅ |
| cn_doh | 国内公共 DoH（托底 + 免过滤回落） | doh.pub / dns.alidns.com | DoH ✅ |
| overseas_doh | CF 隧道反代海外 DoH（托底用） | lumine.misakacloud.dev / kazuha.misakacloud.dev | DoH ✅ |

无明文 UDP:53 出口。

## 健康检查托底

- **self_doh 全部不可用** → 本地模拟公网 AdGuard 分裂：CN 域名走 cn_doh，其他走 overseas_doh
- **self_no_filter 全部不可用** → 回落 cn_doh

## 验证命令

```bash
# 基础解析 / fallback
dig @127.0.0.1 -p 1853 example.com A
dig @127.0.0.1 -p 1853 example.com AAAA

# NXDOMAIN 阻断
dig @127.0.0.1 -p 1853 0--0.info A

# zero-IP 阻断
dig @127.0.0.1 -p 1853 bigme.app A
dig @127.0.0.1 -p 1853 bigme.app AAAA

# allowlist 豁免
dig @127.0.0.1 -p 1853 chiphell.com A

# CN 路由
dig @127.0.0.1 -p 1853 baidu.com A

# EDNS 65001 MAC 观测 + no-filter → cn pool
dig @127.0.0.1 -p 1853 +ednsopt=65001:aabbccddeeff baidu.com A

# no-filter + blocklist 域（绕过阻断）
dig @127.0.0.1 -p 1853 +ednsopt=65001:aabbccddeeff 0--0.info A

# HTTPS / SVCB 策略
dig @127.0.0.1 -p 1853 example.com HTTPS
```

MAC 日志期望：

```text
edns65001_mac_found=aa:bb:cc:dd:ee:ff
```

无 EDNS MAC 时：

```text
edns65001_mac_missing_or_invalid
```

## MAC 设备分类

| 列表文件 | 含义 | 规则链位置 | 路由目标 |
|---|---|---|---|
| `lists/mac-clean.txt` | 需过滤的设备（clean） | 规则 2-5 | allowlist 优先 → blocklist → self_doh（带托底） |
| 不在 clean 列表或无 MAC | 免过滤设备 | 规则 6 | self_no_filter → cn_doh |

格式：每行一个 MAC，hex 无分隔符小写（如 `047c16bf923c`）。

## 迁移全景

| Phase | 内容 | 状态 |
|---|---|---|
| 0 | 验证 dnsdist 读出 OpenWRT MAC | ✅ |
| 1 | dnsdist 2.1.0-rc1 升级 + EDNS 65001 MAC 解析 | ✅ |
| 2 | rule-builder + dnsdist 规则链（blocklist/allowlist） | ✅ |
| 3 | 分流逻辑：MAC 感知 Clean/免过滤 + 全加密出口 | ✅ |
| 4 | compose 服务清理（mosdns/adguard → legacy） | ✅ |
| 5 | 上游池重构（self_doh / self_no_filter / cn_doh / overseas_doh） | ✅ |
| 6 | Ansible 模板化配置生成 | ✅ |
| 7 | 文档清理 + 中文注释 | ✅ |
| 8 | 内建 DoH bootstrap（替代 dnsproxy + 硬编码 IP） | ✅ |

## rule-builder

`rule-builder/rule_builder.py` 下载并解析规则源，输出到 `dnsdist/generated/`。

```bash
python3 rule-builder/rule_builder.py
docker compose restart dnsdist
```

当前动作分配：

| 源 | action |
|---|---|
| AdGuard DNS filter | nxdomain |
| AdAway hosts | nxdomain |
| CHN: AdRules DNS List | nxdomain |
| HaGeZi Pro++ | nxdomain |
| 寄师傅不允许 | zero_ip |

## Ansible

本项目使用 Ansible 生成配置文件。运行方式：

```bash
# 初始化（首次部署）
docker compose --profile init up ansible-init

# 或直接在宿主机运行
ansible-playbook ansible/playbook.yml
```

Ansible 会：

1. 创建必要目录
2. 下载 mosdns 资源和 MAC 列表（存量兼容）
3. 渲染 AdGuardHome / dnsproxy / mosdns 配置（存量兼容）
4. 同步 dnsdist 配置文件和 Lua 脚本（mac.lua、lists.lua、routing.lua）
5. 运行 rule-builder 生成 blocklist
6. 确保 CN 域名列表文件存在

## 自定义镜像构建

```bash
docker build -t dnsdist-custom:2.1.0-rc1 -f Dockerfile.custom-dnsdist .
```

构建说明：

- Stage 1: 编译环境（clang、meson、Rust、quiche 头文件）
- Stage 2: 源码下载
- Stage 3: 全特性 meson 编译 + LTO thin + strip
  - 补丁: `dnsdist-lua-bindings-dnsquestion.cc` — `dq:removeEDNSOption()`
  - 补丁: `dnsdist-lua-bindings-network.cc` — `resolveViaDoH()` / `resolveViaDoHFirst()`
- Stage 4: 基于官方镜像替换二进制

## 已知待办

- DNS-over-QUIC 上游支持（dnsdist quiche 编译已启用，但上游配置尚未接入）。
- rule-builder / CN 列表定时自动更新。
- bootstrap IP 自动刷新：当前仅在 dnsdist 启动/重启时解析一次。后续可考虑通过定时器或 console 命令实现热更新。
