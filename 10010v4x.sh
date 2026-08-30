#!/bin/sh
# 自动加载 config.sh 环境变量 (兼容呆呆面板与青龙面板)
for f in /app/Dumb-Panel/config.sh /app/Dumb-Panel/config/config.sh /docker/daidai/Dumb-Panel/config.sh /ql/data/config/config.sh ./config.sh ../config.sh; do
    if [ -f "$f" ]; then
        . "$f"
    fi
done

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 赋予可执行权限并启动
chmod +x ./10010v4x 2>/dev/null || true
exec ./10010v4x "$@"
