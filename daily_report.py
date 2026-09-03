#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicom-monitor 每日流量日报 (daily_report.py)
- 读取 10010v4x_data.json 的 history, 计算昨日 通用/免流 总消耗与最大单次跳点
- 打印日报到 stdout, 由呆呆面板 / 青龙面板的「任务成功通知」推送
- 仅读取, 不写任何文件, 不影响巡检基线 (与 10010v4x 主程序完全解耦)
- 兼容呆呆面板容器路径 /app/Dumb-Panel 与宿主机 /docker/daidai/Dumb-Panel
用法: python3 daily_report.py [偏移天数, 默认1=昨天]
"""
import json, os, sys, time

TZ = 8 * 3600  # UTC+8, 与主程序一致显式钉死东八区

# 数据文件定位: 容器内路径优先, 其次宿主机挂载路径, 最后脚本同目录
CANDIDATES = [
    '/app/Dumb-Panel/scripts/10010v4x_data.json',      # daidai 容器内
    '/docker/daidai/Dumb-Panel/scripts/10010v4x_data.json',  # OpenWrt 宿主机
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '10010v4x_data.json'),
]
DATA = next((p for p in CANDIDATES if os.path.exists(p)), CANDIDATES[0])

# 套餐通用总量(MB), 用于计算剩余 (冰激凌套餐 套内国内流量 40G; 多账号可按需改为 dict)
PLAN_TOTAL_NORM_MB = 40960.0

offset_days = 1
if len(sys.argv) > 1:
    try:
        offset_days = int(sys.argv[1])
    except ValueError:
        pass

now = int(time.time())
today0 = (now + TZ) // 86400 * 86400 - TZ          # 今日 00:00 CST
target0 = today0 - offset_days * 86400             # 目标日 00:00 CST
target1 = target0 + 86400                          # 次日 00:00 CST

def fmt_mb(mb):
    if mb is None:
        return 'N/A'
    if mb >= 1024:
        return '%.2fG' % (mb / 1024.0)
    return '%.2fM' % mb

def cst(ms):
    return time.strftime('%H:%M', time.gmtime(ms / 1000 + TZ))

if not os.path.exists(DATA):
    print('⚠️ 未找到数据文件: %s' % DATA)
    print('   请在 10010v4x 同目录运行, 或修改脚本顶部 CANDIDATES 路径')
    sys.exit(1)

with open(DATA) as f:
    data = json.load(f)

lines = []
date_str = time.strftime('%Y-%m-%d', time.gmtime(target0 + TZ))
lines.append('📊 联通流量日报 %s' % date_str)
lines.append('=' * 26)

found = False
for acc_id, a in sorted(data.get('accounts', {}).items()):
    hist = [h for h in a.get('history', [])
            if target0 * 1000 <= h['timestamp'] < target1 * 1000]
    if not hist:
        continue
    found = True
    snaps = [h['snapshot'] for h in hist]

    # 当日总消耗 = 末日快照 - 首日快照 (首快照为 00:00 后第一次巡检, 含前日尾量, 误差<=一个巡检周期)
    norm_first, norm_last = snaps[0].get('normalUsed', 0), snaps[-1].get('normalUsed', 0)
    free_first, free_last = snaps[0].get('freeUsed', 0), snaps[-1].get('freeUsed', 0)
    norm_used = max(0, norm_last - norm_first)
    free_used = max(0, free_last - free_first)

    # 最大单次跳点 (相邻快照差)
    max_norm_j, max_free_j, max_t = 0.0, 0.0, ''
    for i in range(1, len(hist)):
        dn = snaps[i].get('normalUsed', 0) - snaps[i - 1].get('normalUsed', 0)
        df = snaps[i].get('freeUsed', 0) - snaps[i - 1].get('freeUsed', 0)
        if dn > max_norm_j:
            max_norm_j, max_t = dn, cst(hist[i]['timestamp'])
        if df > max_free_j:
            max_free_j = df

    last = a.get('last', {}) or {}
    norm_now = last.get('normalUsed') or 0.0
    norm_remain = PLAN_TOTAL_NORM_MB - norm_now
    lines.append('📦 账号 %s' % acc_id[-6:])
    lines.append('• 昨日通用: %s (最大跳点 +%.0fM @%s)' % (fmt_mb(norm_used), max_norm_j, max_t or '--'))
    lines.append('• 昨日免流: %s (最大跳点 +%.0fM)' % (fmt_mb(free_used), max_free_j))
    lines.append('• 当前通用已用: %s / 剩余: %s (共40G)' % (fmt_mb(norm_now), fmt_mb(norm_remain)))
    lines.append('• 当前免流已用: %s' % fmt_mb(last.get('freeUsed')))
    lines.append('-' * 26)

if not found:
    lines.append('⚠️ %s 无巡检快照 (history 仅保留约24h, 需在次日凌晨运行)' % date_str)

print('\n'.join(lines))
