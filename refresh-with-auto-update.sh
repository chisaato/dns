#!/bin/bash

# 重启容器，启用自动更新配置，强制刷新并删除孤儿容器
docker compose --profile auto-update up -d --force-recreate --remove-orphans