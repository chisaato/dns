#!/bin/bash
# 将当前 Git 仓库转为浅层克隆（depth=1），清理历史减小体积
# 适用于在其他设备部署时避免 git pull 传输大量历史

set -e

CURRENT_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "main")

# 检查是否有未提交的修改
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "⚠️  检测到未提交的修改，请先 commit/stash 后再执行。"
    exit 1
fi

# ── Step 1: 如果有远程，转为 depth=1 浅层克隆 ──
if git remote -v | grep -q .; then
    REMOTE=$(git remote | head -1)
    echo "检测到远程仓库（$REMOTE），执行浅层克隆 (depth=1)..."

    git fetch --depth=1 "$REMOTE" "$CURRENT_BRANCH"
    git reset --hard "$REMOTE/$CURRENT_BRANCH"

    echo "已转为 depth=1 的浅层克隆。"
else
    echo "未检测到远程仓库，跳过浅层克隆步骤。"
fi

# ── Step 2: 清理 reflog，释放对旧对象的引用 ──
git reflog expire --expire=now --all

# ── Step 3: 清理远程跟踪分支 ──
git remote prune origin 2>/dev/null || true

# ── Step 4: 清除不可达对象并压缩仓库 ──
git prune --expire=now
git gc --aggressive --prune=now

echo ""
echo "✅ 仓库历史已清理。当前状态："
git count-objects -vH
