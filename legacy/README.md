# 方案 B：Node.js 版 (Node.js Archive & Alternative)

本目录归档存放 Node.js 实现脚本 (`index.js`)，适合需要纯 JS 脚本环境快速调试或不喜欢编译二进制的用户。

### 使用方法：
1. **安装依赖**：`npm install axios`
2. **执行任务**：`node index.js` 或在面板中运行 `task legacy/index.js`
3. **支持特性**：
   - 同样支持三色跳点前缀识别；
   - 支持多账号轮询检测；
   - 支持在线一言 API 与离线精选语录库（`[随机语录]` 占位符）；
   - 支持全平台推送（钉钉、TG、PushPlus 及面板通知网关）。

> 💡 **推荐建议**：生产环境建议优先使用根目录下的 **方案 A：Go 工业级极速版 (`10010v4x`)**，内存占用更低（<4MB）、速度更快（<0.5s）、自带并发文件锁与 Telegram 守护进程。
