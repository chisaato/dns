#!/bin/bash
set -e

IMAGE="rule-builder:latest"
VOLUMES="-v ./:/workdir -w /workdir"

docker run --rm $VOLUMES $IMAGE python3 rule-builder/rule_builder.py

docker compose restart dnsdist
