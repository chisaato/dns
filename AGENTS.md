# AGENTS.md — DNS 分流净化栈（mosdns-x 单进程版）

## 项目是什么

基于 Docker Compose 的 DNS 分流与广告过滤栈。
通过 mosdns-x 单进程完成所有功能：MAC 地址分流、AdGuard urlfilter 广告过滤、字节限制 LRU 缓存、多协议上游转发。

## 关键约束

- **网络模式为 `host`**，不是 bridge。DNS 服务需要直接绑定宿主机端口。
- **配置文件由 Ansible 生成，不要手改**。修改 `vars.yml` 后运行 `./init.sh` 重新生成。
- **`vars.yml` 在 `.gitignore` 中（含密码等敏感信息）**，默认模板在 `ansible/default/default.yml`。
- **运行时数据目录 `mosdns/` 在 `.gitignore` 中**，这些是 Ansible 生成或容器运行产生的数据。

## 工作流

```
1. cp ansible/default/default.yml vars.yml  # 首次部署
2. vim vars.yml                              # 编辑上游 DNS、过滤器 URL 等
3. ./init.sh                                 # Ansible 渲染配置 + 下载 geosite.dat
4. ./refresh.sh                              # 启动/重启所有服务（不含自动更新）
   # 或
4. ./refresh-with-auto-update.sh             # 启动/重启 + 启用 Ofelia 定时更新
```

## 服务架构

```
                 ┌──────────┐
                 │  Client  │ (OpenWRT, 携带 MAC)
                 └────┬─────┘
                      │
                 ┌────▼──────────────────────────┐
                 │          mosdns-x             │
                 │  ┌─────────────────────────┐  │
                 │  │  main_sequence          │  │
                 │  │  ├─ hosts               │  │
                 │  │  ├─ MAC 分流            │  │
                 │  │  │  ├ 干净 → 直出上游   │  │
                 │  │  │  └ 过滤 → adg_filter │  │
                 │  │  ├─ adg_cache (LRU)     │  │
                 │  │  └─ 域名分流 → 上游    │  │
                 │  └─────────────────────────┘  │
                 └────┬──────────────────────────┘
                      │
                 ┌────▼─────┐
                 │ 上游 DNS  │
                 └──────────┘
```

- **MOSDNS** (`ghcr.io/chisaato/mosdns-x`): 单进程核心，集成了 MAC 匹配、AdGuard 过滤引擎（urlfilter）、字节限制 LRU 缓存（golibs/cache）、多协议转发（dnsproxy/upstream）。监听 `mosdns_default_listen`。
- **Ofelia** (`mcuadros/ofelia`): 仅在 `auto-update` profile 下运行，每日更新 `geosite.dat` 和远程 MAC 地址列表。
- **Ansible Init** (`alpine/ansible`): 仅在 `init` profile 下运行的一次性任务，渲染配置文件。

## 常用命令

| 命令 | 作用 |
|------|------|
| `./init.sh` | 生成/更新所有配置文件 |
| `./refresh.sh` | 重启所有服务（无自动更新） |
| `./refresh-with-auto-update.sh` | 重启所有服务（开启自动更新） |
| `./q.sh <domain>` | 快速 DNS 查询（使用 `natesales/q`） |
| `docker compose ps` | 查看运行状态 |

## MOSDNS 配置变量速查（`vars.yml`）

| 变量 | 含义 |
|------|------|
| `bootstrap_dns` | Bootstrap DNS 列表（所有 adg_forward 共享） |
| `mosdns_default_listen` | MOSDNS 主监听端口 |
| `mosdns_oversea_upstream` | 海外 DNS 上游 |
| `mosdns_cn_clean_upstream` | 国内洁净上游（需要过滤的域名走这里） |
| `mosdns_self_no_filter_upstream` | 自建不过滤上游（干净 MAC 直出） |
| `mosdns_cn_normal_upstream` | 国内普通加密 DNS（fallback 用） |
| `adguard_filters` | 广告过滤器列表（直接内置在 mosdns-x 中） |
| `adguard_whitelist_filters` | 白名单过滤器列表 |
| `geosite_dat_url` | geosite.dat 下载地址 |
| `mac_address_remote_url` | 远程 MAC 地址列表下载地址 |
| `mosdns_custom_forwarding` | 自定义域名级别的转发规则 |

## 注意事项

- MAC 地址分流依赖 OpenWRT 的非标准 EDNS 扩展，非 OpenWRT 环境下 MAC 可能无法携带。
- `mosdns/config.yaml` 由 Jinja2 模板渲染，修改后会被 `init.sh` 覆盖。
- Ofelia 使用 Docker socket 控制容器，需要 `/var/run/docker.sock` 可访问。
- 所有上游 DNS 建议使用 DoH/DoQ 协议以保证传输加密。
- adg_forward 内置了 bootstrap pool，不再需要独立的 dnsproxy 容器。
- adg_filter 的规则支持热更新（`update_interval: 86400`），无需 AdGuard Home 独立进程。
