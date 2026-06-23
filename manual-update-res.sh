#!/bin/bash
set -e

IMAGE="ccr.ccs.tencentyun.com/karasu/stck:rule-builder"

docker run -ti --network host --rm -v ./:/workdir -w /workdir $IMAGE python3 rule-builder/rule_builder.py

docker compose restart dnsdist
