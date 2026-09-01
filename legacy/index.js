// ============================================================================
// 联通余量查询与跳点监控 (全功能重构版)
//
// ⚠️ 免责声明: 本项目为纯 AI 生成代码 (AI-Generated Code)，仅供测试与学习
// 研究用途，禁止商业用途与任何违法违规使用，使用后果自负。
// ============================================================================
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const SCRIPT_DIR = __dirname;
const COOKIE_FILE = path.join(SCRIPT_DIR, '10010v4_cookie.txt');
const DATA_STORE_FILE = path.join(SCRIPT_DIR, '10010v4_data.json');

// 单位格式化
function formatFlow(mb, decimals = 2) {
    const num = parseFloat(mb) || 0;
    if (Math.abs(num) < 1024) return `${num.toFixed(decimals)}M`;
    return `${(num / 1024).toFixed(decimals)}G`;
}

function formatDuration(seconds) {
    const s = Math.max(0, Math.floor(seconds));
    if (s < 60) return `${s}秒`;
    if (s < 3600) return `${Math.floor(s / 60)}分钟`;
    if (s < 86400) return `${(s / 3600).toFixed(1)}小时`.replace('.0', '');
    return `${(s / 86400).toFixed(1)}天`.replace('.0', '');
}

// 历史数据存储
function loadStore() {
    try {
        if (fs.existsSync(DATA_STORE_FILE)) {
            const raw = fs.readFileSync(DATA_STORE_FILE, 'utf8');
            if (raw.trim()) return JSON.parse(raw);
        }
    } catch (e) {
        console.log('⚠️ 读取历史数据异常，重新初始化存储');
    }
    return { last: null, today: null };
}

function saveStore(store) {
    try {
        fs.writeFileSync(DATA_STORE_FILE, JSON.stringify(store, null, 2), 'utf8');
    } catch (e) {}
}

// 获取所有 Cookie
function getCookies() {
    let cookieStr = process.env.UNICOM_COOKIE || process.env.ChinaUnicom_10010v4_cookie || '';
    if (!cookieStr && fs.existsSync(COOKIE_FILE)) {
        try {
            cookieStr = fs.readFileSync(COOKIE_FILE, 'utf8').trim();
        } catch (e) {}
    }
    if (!cookieStr) return [];
    
    return cookieStr.split(/[\n&]+/)
        .map(c => c.replace(/^```|```$/g, '').trim())
        .filter(c => c.length > 20);
}

const BUILTIN_QUOTES = [
    '星光不问赶路人，时光不负有心人。',
    '生活明朗，万物可爱，人间值得，未来可期。',
    '不积跬步，无以至千里；不积小流，无以成江海。',
    '每一个不曾起舞的日子，都是对生命的辜负。',
    '愿你历尽千帆，归来仍是少年。',
    '追风赶月莫停留，平芜尽处是春山。',
    '万物皆有裂痕，那是光照进来的地方。',
    '保持热爱，奔赴山海。',
    '知足且上进，温柔且坚定。',
    '心之所向，素履以往，生如逆旅，一苇以航。',
    '山有顶峰，湖有彼岸，在人生漫漫长途中，万物皆有回转。',
    '沉淀自己，默默拔节，终会迎来属于你的繁花似锦。',
    '日出有盼，日落有念，平淡日子里泛着光。',
    '慢品人间烟火色，闲观万事岁月长。',
    '向光而行，不负韶华。',
    '今天也是元气满满、充满希望的一天！',
    '行远自迩，笃行不怠。',
    '岁月漫长，值得等待；心怀浪漫，所遇皆温柔。',
    '博观而约取，厚积而薄发。',
    '愿你眼中有星辰，心中有山海，以梦为马，不负韶华。',
    '无论身在何处，都要像向日葵一样向阳而生。',
    '前路浩浩荡荡，万事尽可期待。',
    '热爱可抵岁月漫长，风雨兼程只为遇见更好的自己。',
    '流水不争先，争的是滔滔不绝。',
    '路虽远，行则将至；事虽难，做则必成。'
];

async function getRandomQuote() {
    const custom = process.env.ChinaUnicom_10010v4_custom_quotes || process.env.CUSTOM_QUOTES;
    if (custom) {
        const list = custom.split(/[\n|]+/).map(s => s.trim()).filter(Boolean);
        if (list.length > 0) return list[Math.floor(Math.random() * list.length)];
    }
    if (process.env.ENABLE_ONLINE_QUOTE !== '0') {
        try {
            const res = await axios.get('https://v1.hitokoto.cn/?encode=text', {
                timeout: 1200,
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            if (res.data && typeof res.data === 'string' && res.data.trim().length > 0 && res.data.length < 120) {
                return res.data.trim();
            }
        } catch (e) {}
    }
    return BUILTIN_QUOTES[Math.floor(Math.random() * BUILTIN_QUOTES.length)];
}

// 模板变量替换
function renderTemplate(tpl, vars) {
    let result = (tpl || '').replace(/\\n/g, '\n');
    for (const [key, value] of Object.entries(vars)) {
        result = result.split(key).join(value !== undefined ? value : '');
    }
    return result;
}

// 多通道消息推送
async function sendNotification(title, content) {
    console.log(`\n==============📣 系统通知 📣==============\n${title}\n\n${content}\n`);

    const notifyPaths = ['./sendNotify', '../sendNotify', '/app/Dumb-Panel/scripts/sendNotify', '/ql/data/scripts/sendNotify'];
    for (const np of notifyPaths) {
        try {
            const notify = require(np);
            if (notify && typeof notify.sendNotify === 'function') {
                await notify.sendNotify(title, content);
                return;
            }
        } catch (e) {}
    }

    if (process.env.DD_BOT_TOKEN) {
        try {
            await axios.post(`https://oapi.dingtalk.com/robot/send?access_token=${process.env.DD_BOT_TOKEN}`, {
                msgtype: 'text',
                text: { content: `${title}\n\n${content}` }
            }, { timeout: 8000 });
            console.log('✅ 钉钉通知发送成功');
        } catch (e) {}
    }

    if (process.env.TG_BOT_TOKEN && process.env.TG_USER_ID) {
        try {
            const host = process.env.TG_API_HOST || 'https://api.telegram.org';
            await axios.post(`${host}/bot${process.env.TG_BOT_TOKEN}/sendMessage`, {
                chat_id: process.env.TG_USER_ID,
                text: `${title}\n\n${content}`
            }, { timeout: 8000 });
            console.log('✅ Telegram 通知发送成功');
        } catch (e) {}
    }

    if (process.env.PUSH_PLUS_TOKEN) {
        try {
            await axios.post('https://www.pushplus.plus/send', {
                token: process.env.PUSH_PLUS_TOKEN,
                title: title,
                content: content.replace(/\n/g, '<br/>'),
                template: 'html'
            }, { timeout: 8000 });
            console.log('✅ PushPlus 微信推送成功');
        } catch (e) {}
    }
}

// 单账号查询处理
async function processAccount(cookie, index = 0) {
    const apiUrl = 'https://m.client.10010.com/servicequerybusiness/operationservice/queryOcsPackageFlowLeftContentRevisedInJune';

    const response = await axios.post(apiUrl, {}, {
        headers: {
            'Cookie': cookie,
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 2211133C Build/UKQ1.230804.001);unicom{version:android@11.0900}',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 16000
    });

    const data = response.data;
    if (!data || data.code !== '0000' || !Array.isArray(data.resources) || data.resources.length === 0) {
        console.error(`❌ [账号 ${index + 1}] 接口返回异常或无资源数据:`, JSON.stringify(data));
        return;
    }

    const packageName = data.packageName || '联通套餐';
    const unicomTime = data.time || new Date().toLocaleString('zh-CN');

    const buckets = {
        freeUnlimited: { used: 0, remain: 0, total: 0 },
        freeLimited:   { used: 0, remain: 0, total: 0 },
        normalUnlimited: { used: 0, remain: 0, total: 0 },
        normalLimited: { used: 0, remain: 0, total: 0 }
    };

    let voiceTotal = 0, voiceUsed = 0, voiceRemain = 0;

    if (Array.isArray(data.resources)) {
        for (const res of data.resources) {
            if (res.type === 'flow' || res.type === 'MlFlowdetailsList') {
                const details = res.details || [];
                for (const item of details) {
                    const name = item.feePolicyName || item.addUpItemName || '';
                    const total = parseFloat(item.total) || 0;
                    const use = parseFloat(item.use) || 0;
                    const remain = parseFloat(item.remain) || 0;
                    const isUnlimited = item.limited === '1' || item.limited === 1 || total <= 0;
                    const isFree = item.flowType === '2' || item.flowType === '3' || res.type === 'MlFlowdetailsList' || /免流|定向|直播|畅视|专享免费/i.test(name);

                    if (isFree) {
                        if (isUnlimited) {
                            buckets.freeUnlimited.used += use;
                        } else {
                            buckets.freeLimited.used += use;
                            buckets.freeLimited.remain += remain;
                            buckets.freeLimited.total += total;
                        }
                    } else {
                        if (isUnlimited) {
                            buckets.normalUnlimited.used += use;
                        } else {
                            buckets.normalLimited.used += use;
                            buckets.normalLimited.remain += remain;
                            buckets.normalLimited.total += total;
                        }
                    }
                }
            }

            if (res.type === 'Voice' && Array.isArray(res.details)) {
                for (const v of res.details) {
                    voiceTotal += parseFloat(v.total) || 0;
                    voiceUsed += parseFloat(v.use) || 0;
                    voiceRemain += parseFloat(v.remain) || 0;
                }
            }
        }
    }

    const freeTotal = buckets.freeUnlimited.total + buckets.freeLimited.total;
    const freeUsed = buckets.freeUnlimited.used + buckets.freeLimited.used;
    const freeRemain = buckets.freeUnlimited.remain + buckets.freeLimited.remain;

    const normalTotal = buckets.normalUnlimited.total + buckets.normalLimited.total;
    const normalUsed = buckets.normalUnlimited.used + buckets.normalLimited.used;
    const normalRemain = buckets.normalUnlimited.remain + buckets.normalLimited.remain;

    const store = loadStore();
    const now = new Date();
    const todayZero = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();

    const currentSnapshot = {
        freeUnlimitedUsed: buckets.freeUnlimited.used,
        freeLimitedUsed: buckets.freeLimited.used,
        freeUsed: freeUsed,
        normalLimitedUsed: buckets.normalLimited.used,
        normalUsed: normalUsed
    };

    if (!store.today || store.today.date !== todayZero) {
        store.today = { date: todayZero, ...currentSnapshot };
    }

    const todayFreeUnlimit = Math.max(0, buckets.freeUnlimited.used - (store.today.freeUnlimitedUsed || 0));
    const todayFreeLimit = Math.max(0, buckets.freeLimited.used - (store.today.freeLimitedUsed || 0));
    const todayFree = Math.max(0, freeUsed - (store.today.freeUsed || 0));

    const todayNormalLimit = Math.max(0, buckets.normalLimited.used - (store.today.normalLimitedUsed || 0));
    const todayNormal = Math.max(0, normalUsed - (store.today.normalUsed || 0));

    store.history = store.history || [];
    const shouldAppend = store.history.length === 0 || (now.getTime() - store.history[store.history.length - 1].time) >= 20000;
    if (shouldAppend) {
        store.history.push({ time: now.getTime(), ...currentSnapshot });
    }
    const oneDayAgo = now.getTime() - 24 * 3600 * 1000;
    store.history = store.history.filter(h => h.time >= oneDayAgo);

    let durationStr = '0秒';
    let diffFreeUnlimit = 0, diffFreeLimit = 0, diffFree = 0;
    let diffNormalLimit = 0, diffNormal = 0;

    let baseSnap = null;
    let baseTime = 0;

    const botMinutes = parseInt(process.env.ChinaUnicom_10010v4_bot_minutes || '30', 10);
    if (botMinutes > 0 && store.history.length > 0) {
        const targetTs = now.getTime() - botMinutes * 60 * 1000;
        let minDiff = Infinity;
        for (const h of store.history) {
            const d = Math.abs(h.time - targetTs);
            if (d < minDiff) {
                minDiff = d;
                baseSnap = h;
                baseTime = h.time;
            }
        }
    }

    if (!baseSnap && store.last && store.last.time) {
        baseSnap = store.last;
        baseTime = store.last.time;
    }

    if (baseSnap && baseTime) {
        const sec = (now.getTime() - baseTime) / 1000;
        durationStr = formatDuration(sec);
        diffFreeUnlimit = Math.max(0, buckets.freeUnlimited.used - (baseSnap.freeUnlimitedUsed || 0));
        diffFreeLimit = Math.max(0, buckets.freeLimited.used - (baseSnap.freeLimitedUsed || 0));
        diffFree = Math.max(0, freeUsed - (baseSnap.freeUsed || 0));
        diffNormalLimit = Math.max(0, buckets.normalLimited.used - (baseSnap.normalLimitedUsed || 0));
        diffNormal = Math.max(0, normalUsed - (baseSnap.normalUsed || 0));
    }

    store.last = { time: now.getTime(), ...currentSnapshot };
    saveStore(store);

    const vars = {
        '[免流不限.已用]': formatFlow(buckets.freeUnlimited.used),
        '[免流不限.剩余]': '0M',
        '[免流不限.总]': '0M',
        '[免流不限.用量]': formatFlow(diffFreeUnlimit),
        '[免流不限.今日用量]': formatFlow(todayFreeUnlimit),

        '[免流有限.已用]': formatFlow(buckets.freeLimited.used),
        '[免流有限.剩余]': formatFlow(buckets.freeLimited.remain),
        '[免流有限.总]': formatFlow(buckets.freeLimited.total),
        '[免流有限.用量]': formatFlow(diffFreeLimit),
        '[免流有限.今日用量]': formatFlow(todayFreeLimit),

        '[所有免流.已用]': formatFlow(freeUsed),
        '[所有免流.剩余]': formatFlow(freeRemain),
        '[所有免流.总]': formatFlow(freeTotal),
        '[所有免流.用量]': formatFlow(diffFree),
        '[所有免流.今日用量]': formatFlow(todayFree),

        '[通用有限.已用]': formatFlow(buckets.normalLimited.used),
        '[通用有限.剩余]': formatFlow(buckets.normalLimited.remain),
        '[通用有限.总]': formatFlow(buckets.normalLimited.total),
        '[通用有限.用量]': formatFlow(diffNormalLimit),
        '[通用有限.今日用量]': formatFlow(todayNormalLimit),

        '[所有通用.已用]': formatFlow(normalUsed),
        '[所有通用.剩余]': formatFlow(normalRemain),
        '[所有通用.总]': formatFlow(normalTotal),
        '[所有通用.用量]': formatFlow(diffNormal),
        '[所有通用.今日用量]': formatFlow(todayNormal),

        '[原始通用.已用]': formatFlow(normalUsed),
        '[原始通用.用量]': formatFlow(diffNormal),
        '[原始通用.今日用量]': formatFlow(todayNormal),
        '[原始免流.已用]': formatFlow(freeUsed),
        '[原始免流.用量]': formatFlow(diffFree),
        '[原始免流.今日用量]': formatFlow(todayFree),

        '[语音.总]': `${voiceTotal}分钟`,
        '[语音.已用]': `${voiceUsed}分钟`,
        '[语音.剩余]': `${voiceRemain}分钟`,

        '[套餐]': packageName,
        '[时长]': durationStr,
        '[联通时间]': unicomTime,
        '[时间]': now.toLocaleTimeString('zh-CN'),
        '[日期时间]': now.toLocaleString('zh-CN')
    };

    const quote = await getRandomQuote();
    vars['[随机语录]'] = quote;
    vars['[一言]'] = quote;
    vars['[语录]'] = quote;

    const defaultTitleTpl = '[套餐]';
    const defaultSubtTpl = '[时长] 跳 [所有通用.用量] 免 [所有免流.用量]';
    const defaultDescTpl = `☸️通用总共 [通用有限.总] 🔯\n☯️通用已用 [通用有限.已用]🕎\n🕉通用剩余 [通用有限.剩余] ☪️\n♒️免流已用 [所有免流.已用] ⛎\n🕉今日通用 [所有通用.今日用量] 🕉\n🕉今日免流 [所有免流.今日用量] 🕉\n♈️联通时间 [联通时间]♌️\n💌语录：[随机语录]`;

    const titleTpl = process.env.ChinaUnicom_10010v4_title || defaultTitleTpl;
    const subtTpl = process.env.ChinaUnicom_10010v4_subt || defaultSubtTpl;
    const descTpl = process.env.ChinaUnicom_10010v4_desc || defaultDescTpl;

    const renderedTitle = renderTemplate(titleTpl, vars);
    const renderedSubt = renderTemplate(subtTpl, vars);
    const renderedDesc = renderTemplate(descTpl, vars);
    const fullPushContent = `${renderedSubt}\n${renderedDesc}`;

    const minUsage = parseFloat(process.env.ChinaUnicom_10010v4_min_usage !== undefined ? process.env.ChinaUnicom_10010v4_min_usage : 0);
    const totalDiffMb = diffNormal + diffFree;

    if (minUsage > 0 && totalDiffMb < minUsage) {
        console.log(`\n⏳ [跳点过滤] 本次跳量 (${totalDiffMb.toFixed(2)}M) 未达到阈值 (${minUsage}M)，静默不推送。`);
        return;
    }

    await sendNotification(renderedTitle, fullPushContent);
}

async function main() {
    console.log(`=== 联通余量监控系统 [${new Date().toLocaleString('zh-CN')}] ===\n`);

    const cookies = getCookies();
    if (cookies.length === 0) {
        console.error('❌ 未找到可用 Cookie！请配置 UNICOM_COOKIE 环境变量。');
        process.exit(0);
    }

    for (let i = 0; i < cookies.length; i++) {
        try {
            await processAccount(cookies[i], i);
        } catch (err) {
            console.error(`❌ [账号 ${i + 1}] 处理异常:`, err.message);
        }
    }

    console.log('\n✅ 所有账号查询完成，正常退出 (退出码 0)');
    process.exit(0);
}

main();
