# 分流净化 DNS

统一 DNS 入口，基于 PowerDNS dnsdist 实现 MAC 感知的分流净化。

## 架构

```text
                     dnsdist (0.0.0.0:1853)
                    /      |       |      \
           fallback      cn    overseas  self_no_filter
        (223.5.5.5)  (DoH CN)  (CF隧道)   (自建DoH)
```

- **dnsdist**：统一 DNS 入口，负责 MAC 解析、分流、阻断、DoH bootstrap
- **mosdns / AdGuardHome**：已迁移到 legacy profile，不再承担运行时解析

> 上游 DoH 服务器的域名解析通过 `resolveViaDoHFirst()` 内建的 DoH bootstrap 完成，
> 不依赖系统 DNS 或外部 dnsproxy，避免明文 DNS 泄漏。
> 详见 [dnsdist/README.md](dnsdist/README.md#doh-bootstrap-解析器)。

## 分流思路

主要通过 OpenWRT 中所支持的携带请求者 MAC 地址功能（EDNS option 65001）。

- **Clean MAC**（`mac-clean.txt`，需过滤的设备）：allowlist 优先 → blocklist（NXDOMAIN / zero-IP）→ **self_doh**（自建公网 AdGuard）
  - 如果 self_doh 全部不可用 → 本地模拟分裂：CN 走 cn_doh，其他走 overseas_doh
- **非 Clean MAC / 无 EDNS**（免过滤设备）：跳过 blocklist → **self_no_filter**（自建无过滤 DoH）
  - 如果 self_no_filter 不可用 → 回落 **cn_doh**（国内公共 DoH）
- **全加密出口**：所有上游均为 DoH/TLS，无明文 UDP:53

## 快速开始

```bash
# 1. 编辑配置
cp ansible/default/default.yml vars.yml
# 编辑 vars.yml 中的 dnsdist 配置

# 2. 初始化
./init.sh

# 3. 启动
docker compose up -d dnsdist

# 4. 验证
dig @127.0.0.1 -p 1853 example.com A
```

详细配置见 [dnsdist/README.md](dnsdist/README.md)。

## 其他脚本

- `q.sh` 调用 `q` 命令行实现快速的 DNS 查询
- `refresh.sh` 刷新/重启整组 Compose
- `refresh-with-auto-update.sh` 刷新/重启，并启用自动更新
