# syntax=docker/dockerfile:1
# Rule Builder - DNS 域名列表生成器
#
# 构建：
#   docker build -t rule-builder:latest -f rule-builder/Dockerfile .
#

FROM python:3.14-alpine

RUN apk add --no-cache bash && pip3 install --no-cache-dir protobuf

WORKDIR /app
COPY rule-builder/*.py ./

CMD ["python3", "rule_builder.py"]
