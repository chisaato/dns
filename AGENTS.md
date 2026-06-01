# AGENTS.md — DNS 分流净化栈

## 项目是什么

基于 Docker Compose 的 DNS 分流与广告过滤栈。通过 MOSDNS 根据客户端 MAC 地址分流：需要过滤的设备走 `mosdns → adguard → 上游`，不需要过滤的设备走 `mosdns → 上游` 直出。DNS Proxy 作为 bootstrap 解析器，解决 mosdns 启动时无法解析上游 DoH/DoQ 域名的问题。

## 关键约束

- **网络模式为 `host`**，不是 bridge。DNS 服务需要直接绑定宿主机端口。
- **配置文件由 Ansible 生成，不要手改**。修改 `vars.yml` 后运行 `./init.sh` 重新生成。
- **`vars.yml` 在 `.gitignore` 中（含密码等敏感信息）**，默认模板在 `ansible/default/default.yml`。
- **运行时数据目录 `adguard/`、`mosdns/`、`dnsproxy/` 全在 `.gitignore` 中**，这些是 Ansible 生成或容器运行产生的数据。

## 工作流

```
1. cp ansible/default/default.yml vars.yml  # 首次部署
2. vim vars.yml                              # 编辑上游 DNS、端口、过滤器等
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
                 ┌────▼─────┐
                 │  MOSDNS  │ (分流路由器, 端口 1853)
                 └──┬───┬───┘
          需要过滤 │       │ 不过滤
        ┌─────────▼─┐  ┌──▼──────────┐
        │  AdGuard  │  │  直接上游   │
        │  (1753)   │  │  (DoH/DoQ)  │
        └─────┬─────┘  └─────────────┘
              │
         ┌────▼─────┐
         │ 上游 DNS  │
         └──────────┘
```

- **MOSDNS** (`ghcr.io/chisaato/mosdns-x`): 核心分流器。默认监听 `mosdns_default_listen`，洁净出口监听 `mosdns_clean_listen`。
- **AdGuard Home** (`adguard/adguardhome`): DNS 过滤。上游指向 MOSDNS 的洁净端口。
- **DNS Proxy** (`adguard/dnsproxy`): Bootstrap 解析器，解决 MOSDNS 启动时无法解析上游 DoH 域名的问题。
- **Ofelia** (`mcuadros/ofelia`): 仅在 `auto-update` profile 下运行，每日更新 `geosite.dat` 和远程 MAC 地址列表。
- **Ansible Init** (`alpine/ansible`): 仅在 `init` profile 下运行的一次性任务，渲染所有配置文件。

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
| `mosdns_default_listen` | MOSDNS 主监听端口 |
| `mosdns_clean_listen` | MOSDNS 洁净出口（给 AdGuard 用） |
| `mosdns_oversea_upstream` | 海外 DNS 上游 |
| `mosdns_cn_clean_upstream` | 国内洁净上游 |
| `mosdns_self_no_filter_upstream` | 自建不过滤上游 |
| `mosdns_custom_forwarding` | 自定义域名级别的转发规则 |
| `geosite_dat_url` | geosite.dat 下载地址 |
| `mac_address_remote_url` | 远程 MAC 地址列表下载地址 |

## 注意事项

- MAC 地址分流依赖 OpenWRT 的非标准 EDNS 扩展，非 OpenWRT 环境下 MAC 可能无法携带。
- `mosdns/config.yaml`、`adguard/AdGuardHome.yaml`、`dnsproxy/config.yaml` 均由 Jinja2 模板渲染，修改后会被 `init.sh` 覆盖。
- Ofelia 使用 Docker socket 控制容器，需要 `/var/run/docker.sock` 可访问。
- 所有上游 DNS 建议使用 DoH/DoQ 协议以保证传输加密。
