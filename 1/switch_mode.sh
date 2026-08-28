#!/bin/sh
# ==========================================================
# 自动切换代理模式脚本 (支持 Termux / Magisk / KernelSU / 自动化软件)
# 接口地址: http://127.0.0.1:9090
# ==========================================================

API_URL="http://127.0.0.1:9090"

# 切换代理组辅助函数
set_proxy() {
    GROUP="$1"
    NODE="$2"
    # 对组名进行 URL 编码以防兼容性问题
    ENCODED_GROUP=$(echo -n "$GROUP" | od -An -tx1 | tr ' ' % | tr -d '\n')
    
    RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null -X PUT \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$NODE\"}" \
        "$API_URL/proxies/$ENCODED_GROUP")
        
    if [ "$RESPONSE" = "204" ] || [ "$RESPONSE" = "200" ]; then
        echo "  [OK] $GROUP -> $NODE"
    else
        # 如果 URL 编码失败，尝试直接传中文字符
        RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null -X PUT \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$NODE\"}" \
            "$API_URL/proxies/$GROUP")
        if [ "$RESPONSE" = "204" ] || [ "$RESPONSE" = "200" ]; then
            echo "  [OK] $GROUP -> $NODE"
        else
            echo "  [FAIL] $GROUP -> $NODE (HTTP $RESPONSE)"
        fi
    fi
}

# 清理当前存活连接
close_connections() {
    curl -s -X DELETE "$API_URL/connections" >/dev/null 2>&1
    echo "  [OK] 已清理旧连接"
}

# ==================== 切换到 WiFi (直连模式) ====================
to_wifi() {
    echo ">>> 正在切换到: WiFi 直连模式..."
    set_proxy "国外出口" "国外非免流"
    set_proxy "国内出口" "直连"
    set_proxy "AI节点" "AI非免流"
    set_proxy "Emby节点" "Emby非免流"
    set_proxy "UDP游戏" "直连"
    close_connections
    echo ">>> 切换完成！当前处于: 直连模式 (WiFi)"
}

# ==================== 切换到 流量 (免流模式) ====================
to_mianliu() {
    echo ">>> 正在切换到: 移动数据免流模式..."
    set_proxy "国外出口" "国外免流"
    set_proxy "国内出口" "国内免流"
    set_proxy "AI节点" "AI免流"
    set_proxy "Emby节点" "Emby免流"
    set_proxy "UDP游戏" "游戏"
    close_connections
    echo ">>> 切换完成！当前处于: 全免流模式 (Cellular)"
}

# ==================== 查看当前节点状态 ====================
status() {
    echo ">>> 当前各分组状态:"
    for GROUP in "国外出口" "国内出口" "AI节点" "Emby节点" "UDP游戏"; do
        CURRENT=$(curl -s "$API_URL/proxies/$GROUP" | grep -o '"now":"[^"]*"' | cut -d'"' -f4)
        if [ -z "$CURRENT" ]; then
            ENCODED_GROUP=$(echo -n "$GROUP" | od -An -tx1 | tr ' ' % | tr -d '\n')
            CURRENT=$(curl -s "$API_URL/proxies/$ENCODED_GROUP" | grep -o '"now":"[^"]*"' | cut -d'"' -f4)
        fi
        echo "  - $GROUP: ${CURRENT:-[未获取到]}"
    done
}

# ==================== 参数处理 ====================
case "$1" in
    wifi|direct|1)
        to_wifi
        ;;
    mianliu|cell|0)
        to_mianliu
        ;;
    status|s)
        status
        ;;
    *)
        echo "用法: $0 {wifi|mianliu|status}"
        echo "  - wifi    : 切换为 WiFi 直连模式"
        echo "  - mianliu : 切换为 移动数据免流模式"
        echo "  - status  : 查看当前各分组节点状态"
        exit 1
        ;;
esac
