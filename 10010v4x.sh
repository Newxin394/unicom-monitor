#!/bin/sh
# 自动加载 config.sh 环境变量 (兼容呆呆面板与青龙面板)
CR=$(printf '\r')
for f in /app/Dumb-Panel/config.sh /app/Dumb-Panel/config/config.sh /docker/daidai/Dumb-Panel/config.sh /ql/data/config/config.sh ./config.sh ../config.sh; do
    if [ -f "$f" ]; then
        # 1. 尝试就地清理文件中的 \r (CRLF -> LF)
        sed -i "s/${CR}\$//" "$f" 2>/dev/null || true
        # 2. 安全加载配置（若仍含 \r 则使用去除后的流加载）
        if grep "${CR}" "$f" >/dev/null 2>&1; then
            eval "$(tr -d '\r' < "$f")" 2>/dev/null || . "$f"
        else
            . "$f"
        fi
    fi
done

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 热更新支持：若存在新二进制，杀死旧进程并无缝替换
if [ -f "./10010v4x.new" ]; then
    killall -9 10010v4x 2>/dev/null || true
    rm -f ./10010v4x 2>/dev/null || true
    mv -f ./10010v4x.new ./10010v4x
fi

# 赋予可执行权限并启动
chmod +x ./10010v4x 2>/dev/null || true
exec ./10010v4x "$@"
