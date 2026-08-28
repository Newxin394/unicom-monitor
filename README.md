# 联通余量查询与跳点监控 (ChinaUnicom Quota Monitor)

> 🚀 轻量、极速、无混淆、支持智能跳点过滤与全平台推送的中国联通余量监控脚本。完美兼容青龙面板与呆呆面板。

## ✨ 特性

- ⚡ **极速执行**：精简重构，Node 原生驱动，执行时间 < 0.5 秒。
- 📊 **智能跳点监测**：自动比对两次查询之间的跳量差额（通用跳量、免流跳量、今日用量）。
- 🔇 **防打扰阈值过滤**：支持设定 `min_usage` 最小跳量，未达到阈值时静默更新数据，不发通知打扰。
- 🔔 **多通道推送**：原生支持 Telegram 机器人、钉钉机器人、微信 PushPlus、Bark 及面板标准 `sendNotify`。
- 🎯 **经典模版排版**：100% 对齐官方 Emoji 经典余量可视化排版。
- 👥 **多账号支持**：支持使用 `&` 或换行配置多个联通账号循环查询。

## 📦 环境变量说明

| 变量名 | 说明 | 必填 | 默认值 / 示例 |
| :--- | :--- | :---: | :--- |
| `UNICOM_COOKIE` | 联通手机营业厅抓取的完整 Cookie | 是 | `acw_tc=...; c_id=...;` |
| `ChinaUnicom_10010v4_min_usage` | 最小跳量推送阈值 (MB) | 否 | `0` (设为 0.01 则有跳量才推送，0 为每次都推) |
| `TG_BOT_TOKEN` | Telegram Bot Token | 否 | `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11` |
| `TG_USER_ID` | Telegram 接收者 User ID | 否 | `123456789` |
| `DD_BOT_TOKEN` | 钉钉自定义机器人 Webhook Access Token | 否 | `xxxxxxxxxxxx` |
| `PUSH_PLUS_TOKEN` | 微信 PushPlus 用户 Token | 否 | `xxxxxxxxxxxx` |

## 🛠️ 定时任务设置

- **青龙面板 / 呆呆面板命令**：`task index.js` 或 `node index.js`
- **定时规则**：`*/5 * * * *` (推荐每 5 分钟查询一次)

## 📄 开源许可

MIT License
