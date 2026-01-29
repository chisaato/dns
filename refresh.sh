#!/bin/bash

# 重启容器，强制刷新并删除孤儿容器
docker compose up -d --force-recreate --remove-orphans