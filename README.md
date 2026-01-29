# 分流净化 DNS

怎么用? 拷贝 ansible/default/default.yml 出来到根目录为 vars.yml 然后编辑你想编辑的.

之后 `./init.sh`

## 分流思路

主要通过 OpenWRT 中所支持的携带请求者 MAC 地址功能,虽然这个东西没有进入到 EDNS 规范里,但起码还是能用的.

对于处于要净化的 MAC 地址,流程是 `mosdns` -> `adguard` -> `上游`

对于不需要净化的 MAC 地址,流程是 `mosdns` -> `上游`

## 其他脚本

- `q.sh` 调用 `q` 命令行实现快速的 DNS 查询
- `refresh.sh` 刷新/重启整组 Compose,但是不启用自动更新
- `refresh-with-auto-update.sh` 刷新/重启整组 Compose,并启用自动更新
