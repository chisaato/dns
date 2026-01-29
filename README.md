# 分流净化 DNS

怎么用? 拷贝 ansible/default/default.yml 出来到根目录为 vars.yml 然后编辑你想编辑的.

之后 `./init.sh`

## 其他脚本

- `q.sh` 调用 `q` 命令行实现快速的 DNS 查询
- `refresh.sh` 刷新/重启整组 Compose,但是不启用自动更新
- `refresh-with-auto-update.sh` 刷新/重启整组 Compose,并启用自动更新
