// ============================================================================
// 联通余量查询与跳点监控 (ChinaUnicom Quota & Traffic Jump Monitor)
//
// ⚠️ 免责声明: 本项目为纯 AI 生成代码 (AI-Generated Code)，仅供测试与学习
// 研究用途，禁止商业用途与任何违法违规使用，使用后果自负。
// 代码中不包含任何真实账号信息，凭据仅保存在使用者本地环境变量/配置文件中。
// ============================================================================

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ======================== 时区固定与自定义错误 ========================

// 显式钉死东八区（CST），解决 Docker/青龙 UTC 时区导致早上 8 点才归零的问题
var cst = time.FixedZone("CST", 8*3600)

// 自定义鉴权异常，区分「网络抖动」与「真实 Cookie 失效」
type AuthError struct {
	Msg string
}

func (e *AuthError) Error() string {
	return e.Msg
}

var ErrAcquireLockTimeout = errors.New("抢占排他锁超时")

// ======================== 基础数据模型 ========================

type UsageSnapshot struct {
	FreeUnlimitedUsed float64 `json:"freeUnlimitedUsed"`
	FreeLimitedUsed   float64 `json:"freeLimitedUsed"`
	FreeUsed          float64 `json:"freeUsed"`
	NormalLimitedUsed float64 `json:"normalLimitedUsed"`
	NormalUsed        float64 `json:"normalUsed"`
}

type SnapshotRecord struct {
	Timestamp int64          `json:"timestamp"`
	Snapshot  *UsageSnapshot `json:"snapshot"`
}

type AccountStore struct {
	Last      *UsageSnapshot   `json:"last,omitempty"`
	LastTime  int64            `json:"lastTime,omitempty"`
	Today     *UsageSnapshot   `json:"today,omitempty"`
	TodayDate int64            `json:"todayDate,omitempty"`
	History   []SnapshotRecord `json:"history,omitempty"`

	// 旧字段，仅用于从单阈值版本升级时迁移，之后不再参与判定
	LastAlertTime int64 `json:"lastAlertTime"`
	// 通用跳点与免流跳点各自独立的上次推送时间，避免互相压制冷却
	LastAlertNorm int64 `json:"lastAlertNorm,omitempty"`
	LastAlertFree int64 `json:"lastAlertFree,omitempty"`

	// 【暴涨防抖】疑似网关脏数据（单次增量异常大）的上次静默时间
	// 首次暴涨静默一次，若下一次巡检仍暴涨则判定为真实跳点放行
	LastSuspiciousTime int64 `json:"lastSuspiciousTime,omitempty"`

	// 【故障计数】连续非认证失败次数，必须持久化：巡检由 cron 每 3 分钟拉起独立进程，
	// 进程内计数器每次都从 0 开始，"连续 N 次失败"告警永远无法触发。
	// FailStreakAt 记录最后一次失败时间，用于超时后自动重置（避免跨天累积误报）。
	FailStreak   int   `json:"failStreak,omitempty"`
	FailStreakAt int64 `json:"failStreakAt,omitempty"`
}

type StoreData struct {
	Accounts         map[string]*AccountStore `json:"accounts"`
	OwnerID          string                   `json:"ownerId"`
	TGOffset         int64                    `json:"tgOffset"`
	LastFaultAlertAt int64                    `json:"lastFaultAlertAt"`
	Cookies          []string                 `json:"cookies,omitempty"`

	// 【自动登录】按手机号索引的凭据表，是轮换后凭据的唯一权威来源。
	// 用 map 而非按行数组：换新 Cookie 后手机号不变，既不会因行号错位串号，
	// 又天然与 flock 临界区共享同一份 JSON，避免独立文件的锁外读改写竞态。
	Creds map[string]*Credential `json:"creds,omitempty"`

	// 旧版全局 epoch 指纹，仅用于从"整段 env 指纹"版本升级时迁移，之后不再参与判定
	LoginEnvEpoch string `json:"loginEnvEpoch,omitempty"`
}

// Credential 单账号的自动登录凭据。
// EnvEpoch 记录"本条凭据当初替换掉的那行 env 配置的指纹"：
// env 行未变时文件凭据持续接管，用户改了 env 行（指纹变化）则 env 立即重新生效。
// 指纹按行计算，因此修改某一个账号的 env 不会击穿其它账号。
type Credential struct {
	Mobile      string `json:"mobile,omitempty"`
	Cookie      string `json:"cookie,omitempty"`
	TokenOnline string `json:"tokenOnline,omitempty"`
	EnvEpoch    string `json:"envEpoch,omitempty"`
	UpdatedAt   int64  `json:"updatedAt,omitempty"`
}

type QueryResult struct {
	DurationStr string
	DiffNormal  float64
	DiffFree    float64
	TotalDiffMb float64
	AutoTitle   string
	AutoContent string
	BotContent  string
	AccKey      string
	// 账号下标，供报警消息的内联键盘编码"刷新哪个账号"
	AccountIndex int
	// 距上次巡检的分钟数（用于速率感知阈值与通知速率展示）
	ElapsedMinutes float64
	// 本次是否为暴涨防抖静默轮（仅记录基线，不推送）
	SurgeSkipped bool
	// 通用有限池增量（normal_limited_only 判定口径使用）
	DiffNormLimit float64
}

// ======================== 全局变量与配置 ========================

var (
	execSelf   string
	scriptDir  string
	dataFile   string
	bakFile    string
	lockFile   string
	pidFile    string
	cookieFile string

	tokenOnlineFile string

	tgBotToken   string
	tgUserID     string
	tgApiHost    string
	tgBindSecret string
	ddBotToken   string
	ddBotSecret  string // 钉钉「加签」密钥，SEC 开头

	minNormUsage float64 // 通用流量跳点阈值，默认 50M
	minFreeUsage float64 // 免流流量跳点阈值，默认 400M

	botDiffMinutes    int           // /diff 不带参数时的回溯时长（分钟），默认 30；不影响键盘按钮
	alertBypassMb     float64       // 通用跳点超此值时无视冷却
	alertCooldown     time.Duration // 通用跳点冷却
	freeAlertCooldown time.Duration // 免流跳点冷却
	faultCooldown     time.Duration // 故障告警冷却

	// 【账期日】联通套餐结算日（默认 1 号），防抖保护在账期日当天放行归零重置
	billingDay int
	// 【速率感知】按"3 分钟窗口速率"判定跳点达标的换算阈值
	rateWindowMinutes float64 = 3
	// 【暴涨防抖】单次增量超过套餐总量 50% 或超过 1024M 视为疑似脏数据，静默一次
	surgeThreshold float64 = 1024
	// 【暴涨确认窗】首次静默后，在此窗口内再次暴涨才判定为真实跳点（秒）
	surgeConfirmWindow int64 = 600

	// 【判定口径】normalLimitedOnly=1 时通用通道仅用"通用有限池"增量参与阈值判定（展示口径不变）
	normalLimitedOnly bool
	// 【免流关键词】默认关键词之外的用户自定义免流判定关键词（flowType 缺省时生效）
	freeKeywordsExtra []string
	// 【排除名单】命中即跳过统计的干扰项关键词（如日租宝、赠款等）
	excludeKeywords []string
	// 【历史轨迹】快照保留时长（小时，默认 24；加大可支持更长 /diff 回溯）
	historyKeepHours float64 = 24
	// 【分流调试】ChinaUnicom_10010v4_debug=1 时打印每条明细的分桶结果
	debugFlow bool

	isQueryingAtomic  int32
	lastManualQueryAt int64
	manualCooldownSec int64 = 10

	// atomic.Bool 消除多 goroutine 下的 Data Race
	storeMainHealthy atomic.Bool

	httpClient = &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       10,
			IdleConnTimeout:    60 * time.Second,
			DisableCompression: false,
		},
	}

	tgPollClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:       5,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: false,
		},
	}
)

func init() {
	storeMainHealthy.Store(true)

	var err error
	execSelf, err = os.Executable()
	if err != nil {
		execSelf = os.Args[0]
	}

	// 智能定位脚本持久化数据目录：
	// 1. 优先使用面板显式注入的脚本根目录（呆呆面板 DAIDAI_SCRIPTS_DIR、青龙 QL_DIR 等）
	// 2. 识别并规避 `go run` 产生的临时缓存目录 (/tmp/go-build*)
	// 3. 回退到真实可执行文件所在目录或当前工作目录
	//
	// 这两个引导变量必须用 os.Getenv 直读：getEnv 会触发 config.sh 的 sync.Once 加载，
	// 而 config.sh 的候选路径依赖 scriptDir——此刻 scriptDir 尚未赋值，
	// 一旦提前消费 Once，"脚本目录/config.sh" 将永久退化为相对 CWD 的路径且无法重建。
	if envDir := strings.TrimSpace(os.Getenv("DAIDAI_SCRIPTS_DIR")); envDir != "" {
		scriptDir = envDir
	} else if qlDir := strings.TrimSpace(os.Getenv("QL_DIR")); qlDir != "" {
		scriptDir = filepath.Join(qlDir, "data", "scripts")
		if _, err := os.Stat(scriptDir); err != nil {
			scriptDir = filepath.Join(qlDir, "scripts")
		}
	} else {
		exeDir := filepath.Dir(execSelf)
		if strings.Contains(exeDir, "go-build") || strings.HasPrefix(exeDir, os.TempDir()) {
			if cwd, err := os.Getwd(); err == nil {
				scriptDir = cwd
			} else {
				scriptDir = "."
			}
		} else {
			scriptDir = exeDir
		}
	}

	// 若当前由 go run 临时构建启动，修正 execSelf 指向持久化二进制（若存在）
	if strings.Contains(execSelf, "go-build") || strings.HasPrefix(execSelf, os.TempDir()) {
		persistentBin := filepath.Join(scriptDir, "10010v4x")
		if _, statErr := os.Stat(persistentBin); statErr == nil {
			execSelf = persistentBin
		}
	}

	dataFile = filepath.Join(scriptDir, "10010v4x_data.json")
	bakFile = filepath.Join(scriptDir, "10010v4x_data.json.bak")
	lockFile = filepath.Join(scriptDir, "10010v4x_store.lock")
	pidFile = filepath.Join(scriptDir, "10010v4x_tg_bot.pid")
	cookieFile = filepath.Join(scriptDir, "10010v4_cookie.txt")
	tokenOnlineFile = filepath.Join(scriptDir, "10010v4_token_online.txt")

	// 清理历史崩溃遗留的 .tmp 中间文件。
	// 只删 5 分钟前的：cron 巡检进程与 daemon 并存，无条件删会抢掉
	// 对方刚写完、还没 rename 的临时文件，导致那次写入失败。
	if matches, _ := filepath.Glob(dataFile + ".*.tmp"); len(matches) > 0 {
		staleBefore := time.Now().Add(-5 * time.Minute)
		for _, p := range matches {
			if fi, err := os.Stat(p); err == nil && fi.ModTime().Before(staleBefore) {
				_ = os.Remove(p)
			}
		}
	}

	tgBotToken = getEnv("TG_BOT_TOKEN", "")
	tgUserID = getEnv("TG_USER_ID", "")
	tgApiHost = getEnv("TG_API_HOST", "https://api.telegram.org")
	tgBindSecret = getEnv("TG_BIND_SECRET", "")
	ddBotToken = getEnv("DD_BOT_TOKEN", "")
	ddBotSecret = getEnv("DD_BOT_SECRET", "")

	// 通用流量跳点阈值，默认 50M；填 0 表示关闭通用告警
	minNormUsage, err = strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_min_usage", "50"), 64)
	if err != nil || minNormUsage < 0 {
		minNormUsage = 50
	}

	// 免流流量跳点阈值，默认 400M；填 0 表示关闭免流告警
	minFreeUsage, err = strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_min_free_usage", "400"), 64)
	if err != nil || minFreeUsage < 0 {
		minFreeUsage = 400
	}

	// /diff 不带参数时的回溯时长（分钟），默认 30。填 0 或负数视为未配置、回落 30；
	// "对比上次巡检"请用 /check，不要靠这里填 0
	bMin, _ := strconv.Atoi(getEnv("ChinaUnicom_10010v4_bot_minutes", "30"))
	if bMin <= 0 {
		bMin = 30
	}
	botDiffMinutes = bMin

	// 越级放行只看通用跳点，避免免流不限量把这条通道常年顶开
	alertBypassMb, _ = strconv.ParseFloat(getEnv("ALERT_BYPASS_MB", "0"), 64)
	if alertBypassMb < 0 {
		alertBypassMb = 0
	}

	cdSec, _ := strconv.ParseInt(getEnv("TG_CHECK_COOLDOWN_SEC", "10"), 10, 64)
	if cdSec <= 0 {
		cdSec = 10
	}
	manualCooldownSec = cdSec

	// 通用跳点冷却，默认 0（不限制）
	alertCdSec, _ := strconv.Atoi(getEnv("ChinaUnicom_10010v4_cooldown", "0"))
	if alertCdSec < 0 {
		alertCdSec = 0
	}
	alertCooldown = time.Duration(alertCdSec) * time.Second

	// 免流跳点冷却，默认 1800 秒（30分钟）
	// 解析失败（env 写错，如 "30min"）必须回落默认值：静默取 0 会让冷却失效，
	// 免流跳点每轮巡检都推送，等于把配置笔误变成通知风暴
	freeCdSec, freeCdErr := strconv.Atoi(getEnv("ChinaUnicom_10010v4_free_cooldown", "1800"))
	if freeCdErr != nil {
		freeCdSec = 1800
	} else if freeCdSec < 0 {
		freeCdSec = 0
	}
	freeAlertCooldown = time.Duration(freeCdSec) * time.Second

	faultCdSec, _ := strconv.Atoi(getEnv("ChinaUnicom_10010v4_fault_cd", "3600"))
	if faultCdSec < 60 {
		faultCdSec = 60
	}
	faultCooldown = time.Duration(faultCdSec) * time.Second

	// 账期日（默认 1 号），防抖保护在账期日放行归零
	billingDay, _ = strconv.Atoi(getEnv("ChinaUnicom_10010v4_billing_day", "1"))
	if billingDay < 1 || billingDay > 31 {
		billingDay = 1
	}

	// 速率感知窗口（分钟，默认 3 = 与巡检周期一致）
	if rw, _ := strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_rate_window_min", "3"), 64); rw > 0 {
		rateWindowMinutes = rw
	}

	// 暴涨防抖阈值（MB，默认 1024；0 关闭防抖）
	// 必须校验 err：解析失败时 ParseFloat 返回 0，而 0 恰好满足 >= 0，
	// 会把"env 写错"静默变成"关闭防抖"这一功能性降级
	if st, err := strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_surge_threshold_mb", "1024"), 64); err == nil && st >= 0 {
		surgeThreshold = st
	}

	// 暴涨确认窗口（秒，默认 600 = 10 分钟）
	if sw, _ := strconv.ParseInt(getEnv("ChinaUnicom_10010v4_surge_confirm_sec", "600"), 10, 64); sw > 0 {
		surgeConfirmWindow = sw
	}

	// 分流调试开关（打印每条明细的 flowType/分桶结果，用于校准分类规则）
	debugFlow = getEnv("ChinaUnicom_10010v4_debug", "0") == "1"

	// 自定义免流关键词（逗号/顿号/竖线分隔），追加到默认关键词表（flowType 缺省时生效）
	freeKeywordsExtra = splitKeywords(getEnv("ChinaUnicom_10010v4_free_keywords", ""))

	// 排除名单（逗号/顿号/竖线分隔），命中的明细不参与任何统计（如日租宝、定向赠款等干扰项）
	excludeKeywords = splitKeywords(getEnv("ChinaUnicom_10010v4_exclude_keywords", ""))

	// 通用判定口径：1 = 仅"通用有限池"增量参与通用阈值/速率/越级判定（推荐含不限量池套餐开启）
	normalLimitedOnly = getEnv("ChinaUnicom_10010v4_normal_limited_only", "0") == "1"

	// 历史轨迹保留时长（小时，默认 24，上限 720 = 30 天）
	if hh, err := strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_history_hours", "24"), 64); err == nil && hh >= 1 && hh <= 720 {
		historyKeepHours = hh
	}
}

// ======================== 通用工具函数 ========================

func absInt64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

var (
	configShCache map[string]string
	configShOnce  sync.Once
)

func loadConfigSh() {
	configShOnce.Do(func() {
		configShCache = make(map[string]string)
		paths := []string{
			filepath.Join(scriptDir, "..", "config.sh"),
			filepath.Join(scriptDir, "config.sh"),
			filepath.Join(scriptDir, "config", "config.sh"),
			"/app/Dumb-Panel/config.sh",
			"/docker/daidai/Dumb-Panel/config.sh",
			"/ql/data/config/config.sh",
		}
		for _, p := range paths {
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "=") {
					continue
				}
				trimmed = strings.TrimPrefix(trimmed, "export ")
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					if idx := strings.Index(v, " ##"); idx != -1 {
						v = strings.TrimSpace(v[:idx])
					}
					v = strings.Trim(v, "\"'`")
					if _, exists := configShCache[k]; !exists {
						configShCache[k] = v
					}
				}
			}
		}
	})
}

func getEnv(key, def string) string {
	val := os.Getenv(key)
	if strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	loadConfigSh()
	if v, ok := configShCache[key]; ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func formatFlow(mb float64) string {
	if mb < 1024 && mb > -1024 {
		return fmt.Sprintf("%.2fM", mb)
	}
	return fmt.Sprintf("%.2fG", mb/1024)
}

func thresholdText(v float64) string {
	if v <= 0 {
		return "关闭"
	}
	return formatFlow(v)
}

func cooldownText(d time.Duration) string {
	if d <= 0 {
		return "无"
	}
	return d.String()
}

// 只裁剪小数部分的尾零，整数原样返回
func trimZero(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	return strings.TrimRight(strings.TrimRight(s, "0"), ".")
}

func formatDuration(d time.Duration) string {
	s := int64(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%d秒", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%d分钟", s/60)
	}
	if s < 86400 {
		return fmt.Sprintf("%s小时", trimZero(fmt.Sprintf("%.1f", float64(s)/3600)))
	}
	return fmt.Sprintf("%s天", trimZero(fmt.Sprintf("%.1f", float64(s)/86400)))
}

// ======================== 随机语录生成引擎 ========================

var builtinQuotes = []string{
	"星光不问赶路人，时光不负有心人。",
	"生活明朗，万物可爱，人间值得，未来可期。",
	"不积跬步，无以至千里；不积小流，无以成江海。",
	"每一个不曾起舞的日子，都是对生命的辜负。",
	"愿你历尽千帆，归来仍是少年。",
	"追风赶月莫停留，平芜尽处是春山。",
	"万物皆有裂痕，那是光照进来的地方。",
	"保持热爱，奔赴山海。",
	"知足且上进，温柔且坚定。",
	"心之所向，素履以往，生如逆旅，一苇以航。",
	"山有顶峰，湖有彼岸，在人生漫漫长途中，万物皆有回转。",
	"沉淀自己，默默拔节，终会迎来属于你的繁花似锦。",
	"日出有盼，日落有念，平淡日子里泛着光。",
	"慢品人间烟火色，闲观万事岁月长。",
	"向光而行，不负韶华。",
	"今天也是元气满满、充满希望的一天！",
	"行远自迩，笃行不怠。",
	"岁月漫长，值得等待；心怀浪漫，所遇皆温柔。",
	"博观而约取，厚积而薄发。",
	"愿你眼中有星辰，心中有山海，以梦为马，不负韶华。",
	"无论身在何处，都要像向日葵一样向阳而生。",
	"前路浩浩荡荡，万事尽可期待。",
	"热爱可抵岁月漫长，风雨兼程只为遇见更好的自己。",
	"流水不争先，争的是滔滔不绝。",
	"路虽远，行则将至；事虽难，做则必成。",
}

func getRandomQuote() string {
	// 1. 若配置了自定义语录（以换行或 | 分隔）
	if custom := getEnv("ChinaUnicom_10010v4_custom_quotes", getEnv("CUSTOM_QUOTES", "")); custom != "" {
		var list []string
		for _, q := range strings.FieldsFunc(custom, func(r rune) bool { return r == '\n' || r == '|' }) {
			t := strings.TrimSpace(q)
			if t != "" {
				list = append(list, t)
			}
		}
		if len(list) > 0 {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			return list[r.Intn(len(list))]
		}
	}

	// 2. 在线获取一言（极速 1.2 秒超时，失败或未开启则优雅回退）
	if getEnv("ENABLE_ONLINE_QUOTE", "1") != "0" {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", "https://v1.hitokoto.cn/?encode=text", nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
			if resp, err := httpClient.Do(req); err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				if body, err := io.ReadAll(resp.Body); err == nil {
					text := strings.TrimSpace(string(body))
					if len(text) > 0 && len(text) < 120 {
						return text
					}
				}
			}
		}
	}

	// 3. 本地精选语录兜底
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return builtinQuotes[r.Intn(len(builtinQuotes))]
}

// renderTemplate 单遍扫描替换占位符。
//
// 两条约束决定了这个实现：
//   - 按长度降序匹配，防止 [所有通用.用量] 被 [所有通用.用] 短键截胡
//   - 单遍扫描（而非逐键 ReplaceAll 多遍），已替换进来的值不再参与后续匹配。
//     多遍替换下，套餐名等接口字段里只要出现形似占位符的文本，就会被二次替换。
func renderTemplate(tpl string, vars map[string]string) string {
	src := strings.ReplaceAll(tpl, "\\n", "\n")

	keys := make([]string, 0, len(vars))
	for k := range vars {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	var b strings.Builder
	b.Grow(len(src))
	for i := 0; i < len(src); {
		matched := false
		for _, k := range keys {
			if strings.HasPrefix(src[i:], k) {
				b.WriteString(vars[k])
				i += len(k)
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

func toFloat(v interface{}) float64 {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

// toFloatPresence 与 toFloat 相同，但额外返回字段是否存在（区分"字段缺省"与"真为 0"）
func toFloatPresence(v interface{}) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// matchAnyKeyword 判断名称是否命中任意关键词
func matchAnyKeyword(name string, keywords []string) bool {
	for _, kw := range keywords {
		if kw != "" && strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// splitKeywords 按逗号/中文逗号/顿号/竖线/分号拆分关键词，去空白与空项
func splitKeywords(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == '、' || r == '|' || r == ';' || r == '；'
	})
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// lastSnapshotBeforeMs 返回时间戳 <= ts 的最后一条历史记录下标（History 按时间升序），无则 -1
func lastSnapshotBeforeMs(history []SnapshotRecord, ts int64) int {
	for i := len(history) - 1; i >= 0; i-- {
		if history[i].Timestamp <= ts {
			return i
		}
	}
	return -1
}

// ======================== 容灾存储引擎 ========================

// writeFileAtomic 断电安全的原子写：写临时文件 → fsync 数据 → rename → fsync 目录项。
//
// 两次 Sync 都不可省。POSIX 对"rename 返回后新文件内容已在盘上"零保证：
// 数据块可以晚于目录项提交。路由器闪存断电时，只做 tmp+rename 会留下
// 长度正确但内容全零/截断的 JSON——主数据与 .bak 可同时损毁，历史基线全灭。
func writeFileAtomic(path string, raw []byte, perm os.FileMode) error {
	tmp := fmt.Sprintf("%s.%d.%d.tmp", path, os.Getpid(), time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// rename 本身也需要持久化，否则断电后可能回到 rename 之前的状态
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// 抢排他锁 → 读 → 改 → 原子落盘。updater 返回 false 表示无需写盘。
func lockAndModifyStore(updater func(*StoreData) bool) (*StoreData, error) {
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	start := time.Now()
	var locked bool

	for time.Since(start) < 4*time.Second {
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			locked = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	// 抢不到锁必须报错返回，绝不能带着旧数据继续写
	if !locked {
		return nil, ErrAcquireLockTimeout
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	store, loadErr := loadStore()
	if loadErr != nil {
		// 读 IO 错误（EIO/权限等）下无法判断主数据死活，本轮绝不写盘：
		// 否则会把 .bak 的旧快照覆盖到可能完好的主文件上
		return nil, fmt.Errorf("主数据读取失败，本轮拒绝写盘: %w", loadErr)
	}

	if !updater(store) {
		return store, nil
	}

	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return nil, err
	}

	// 只在主数据本身健康时才刷新 .bak（避免用坏数据备份坏数据）
	if storeMainHealthy.Load() {
		if oldRaw, err := os.ReadFile(dataFile); err == nil {
			var check StoreData
			if json.Unmarshal(oldRaw, &check) == nil && check.Accounts != nil {
				_ = writeFileAtomic(bakFile, oldRaw, 0644)
			}
		}
	}

	if err := writeFileAtomic(dataFile, raw, 0644); err != nil {
		return nil, err
	}
	storeMainHealthy.Store(true)

	return store, nil
}

// loadStore 读取主数据，区分三种结果：
//   - (store, nil)：读取成功，或首次运行（文件不存在）
//   - (store, nil) 且 storeMainHealthy=false：读成功但 JSON 损坏，已从 .bak 找回
//   - (nil, err)：读 IO 错误，主数据死活未知——调用方必须拒绝写盘
//
// 把"读失败"和"JSON 损坏"分开是关键：只有确凿损坏才允许回退 .bak，
// 否则一次闪存读抖动就会让 .bak 的旧数据覆盖健康的主文件。
func loadStore() (*StoreData, error) {
	store := &StoreData{Accounts: make(map[string]*AccountStore)}
	storeMainHealthy.Store(true)

	raw, readErr := os.ReadFile(dataFile)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			// 首次运行：主数据尚未生成，不是损坏
			return store, nil
		}
		return nil, readErr
	}

	if json.Unmarshal(raw, store) == nil {
		if store.Accounts == nil {
			store.Accounts = make(map[string]*AccountStore)
		}
		return store, nil
	}

	// 读成功但解析失败 = 确凿损坏，回退 .bak
	storeMainHealthy.Store(false)
	fmt.Println("⚠️ [存储] 主数据损坏，尝试用 .bak 恢复...")

	store = &StoreData{Accounts: make(map[string]*AccountStore)}
	if bakRaw, err := os.ReadFile(bakFile); err == nil {
		if json.Unmarshal(bakRaw, store) == nil {
			if store.Accounts == nil {
				store.Accounts = make(map[string]*AccountStore)
			}
			fmt.Println("✅ [存储] 已从 .bak 找回基线数据")
			return store, nil
		}
	}

	return store, nil
}

// loadStoreSafe 是只读调用方的便捷包装：读 IO 错误时返回空 store 而非报错。
// 只用于展示与判断，绝不能把它的结果写回磁盘（写路径必须走 loadStore）。
func loadStoreSafe() *StoreData {
	store, err := loadStore()
	if err != nil || store == nil {
		return &StoreData{Accounts: make(map[string]*AccountStore)}
	}
	return store
}

// getCookies 返回本轮要巡检的 Cookie 列表（顺序即账号顺序）。
//
// 凭据来源与优先级（逐行独立判定，不是整段一刀切）：
//  1. env 行（UNICOM_COOKIE / ChinaUnicom_10010v4_cookie，按换行分账号）
//  2. 若该行对应的手机号在 store.Creds 中已有轮换凭据，且那条凭据记录的
//     EnvEpoch 与当前 env 行指纹一致（= env 行没被用户改过），则用轮换后的新 Cookie
//  3. env 为空时回落 cookieFile，再回落 store.Cookies
//
// 逐行判定是关键：修改某一个账号的 env 行只会让该行回到 env 控制，
// 其余账号仍继续使用各自已轮换的新凭据。
func getCookies() []string {
	envCookie := getEnv("UNICOM_COOKIE", getEnv("ChinaUnicom_10010v4_cookie", ""))
	envToks := splitCookieLines(getEnv("ChinaUnicom_10010v4_token_online", ""))

	list := splitCookieLines(envCookie)
	if len(list) == 0 {
		// env 未配置：回落文件，再回落 store（独立 daemon 进程在空 env 下依然可用）
		if data, err := os.ReadFile(cookieFile); err == nil {
			list = splitCookieLines(string(data))
		}
		if len(list) == 0 {
			if st := loadStoreSafe(); st != nil && len(st.Cookies) > 0 {
				return st.Cookies
			}
			return nil
		}
		return list
	}

	// env 有配置：逐行检查是否已被自动登录接管
	st := loadStoreSafe()
	if st != nil && len(st.Creds) > 0 {
		takenOver := 0
		for i, ck := range list {
			mobile := mobileFromCookie(ck)
			if mobile == "" {
				continue
			}
			cred := st.Creds[mobile]
			if cred == nil || cred.Cookie == "" {
				continue
			}
			envTok := ""
			if i < len(envToks) {
				envTok = envToks[i]
			}
			if cred.EnvEpoch != "" && cred.EnvEpoch == envCredFingerprint(ck, envTok) {
				list[i] = cred.Cookie
				takenOver++
			}
		}
		if takenOver > 0 {
			fmt.Printf("🔓 [自动登录] %d 个账号的 env Cookie 已被轮换接管，使用 store 中的新凭据\n", takenOver)
		}
	}

	// 落盘一份供独立进程兜底（内容变化才写，避免无意义 IO 与闪存磨损）
	joined := strings.Join(list, "\n")
	if old, err := os.ReadFile(cookieFile); err != nil || strings.TrimSpace(string(old)) != joined {
		_ = writeFileAtomic(cookieFile, []byte(joined), 0600)
	}
	_, _ = lockAndModifyStore(func(s *StoreData) bool {
		if strings.Join(s.Cookies, "\n") != joined {
			s.Cookies = append([]string(nil), list...)
			return true
		}
		return false
	})

	return list
}

// ======================== TokenOnline 自动登录 (Cookie 失效自愈) ========================

// 联通手厅登录协议常量（逆向自原版脚本并实测验证）
const (
	unicomOnlineURL = "https://m.client.10010.com/mobileService/onLine.htm"
	unicomLoginURL  = "https://m.client.10010.com/mobileService/login.htm"
	unicomLoginUA   = "Dalvik/2.1.0 (Linux; U; Android 14; 2211133C Build/UKQ1.230804.001);unicom{version:android@11.0900}"
	unicomAppID     = "ChinaunicomMobileBusiness"
	unicomAppVer    = "android@11.0900"
)

// 联通手厅登录 RSA 公钥 (PKCS#1 v1.5, 与 JSEncrypt 兼容)
const unicomPubKeyB64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7yO9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQgE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNqjBUxzMeQlEC2czEMSwIDAQAB"

// envCredFingerprint 生成单行 env 凭据指纹（该行 cookie + 该行 token_online 的 md5 前 16 位）。
// 按行计算是刻意的：只改一个账号的 env 行时，其余账号的指纹不变、轮换凭据继续生效。
func envCredFingerprint(cookie, tokenOnline string) string {
	sum := md5.Sum([]byte(strings.TrimSpace(cookie) + "|" + strings.TrimSpace(tokenOnline)))
	return hex.EncodeToString(sum[:])[:16]
}

// tokenOnlineForAccount 取第 idx 个账号（手机号 mobile）当前应使用的 token_online。
//
// 与 Cookie 同一套逐行接管规则：store.Creds 里该手机号的凭据若记录了
// 与当前 env 第 idx 行一致的 EnvEpoch，说明 env 行尚未被用户更新，用轮换后的新 token；
// 否则用 env 行本身。行号口径与 getCookies 保持一致（都按 env 行序）。
func tokenOnlineForAccount(st *StoreData, mobile string, idx int) string {
	envCk, envTok := envCredLine(idx)

	if mobile != "" && st != nil {
		if cred := st.Creds[mobile]; cred != nil && cred.TokenOnline != "" {
			// env 未配置该行 → 无从比对，直接用轮换值
			if envTok == "" {
				return cred.TokenOnline
			}
			// env 行仍是被替换时的那份 → 轮换值接管
			if cred.EnvEpoch != "" && cred.EnvEpoch == envCredFingerprint(envCk, envTok) {
				return cred.TokenOnline
			}
		}
	}

	if envTok != "" {
		return envTok
	}
	// env 与 store 都没有：回落历史遗留的 token 文件（老版本升级路径）
	if fileToks := readLinesFile(tokenOnlineFile); idx < len(fileToks) {
		return fileToks[idx]
	}
	return ""
}

// envCredLine 返回 env 配置中第 idx 个账号的 (cookie 行, token_online 行)。
// 两个 env 变量都按换行分账号，行号一一对应。
func envCredLine(idx int) (string, string) {
	envCks := splitCookieLines(getEnv("UNICOM_COOKIE", getEnv("ChinaUnicom_10010v4_cookie", "")))
	envToks := splitCookieLines(getEnv("ChinaUnicom_10010v4_token_online", ""))
	ck, tok := "", ""
	if idx >= 0 && idx < len(envCks) {
		ck = envCks[idx]
	}
	if idx >= 0 && idx < len(envToks) {
		tok = envToks[idx]
	}
	return ck, tok
}

// migrateLegacyCreds 把旧版按行文件的凭据（10010v4_cookie.txt / 10010v4_token_online.txt
// 加全局 LoginEnvEpoch）一次性迁入 store.Creds。
//
// 不迁移会造成真实故障：旧版把轮换后的 token_online 只写进文件，env 里那份早已作废。
// 升级后若 Creds 为空，tokenOnlineForAccount 会优先拿 env 的废 token 去登录并失败，
// 自动登录自愈能力就此丢失。
func migrateLegacyCreds() {
	st := loadStoreSafe()
	if st == nil || len(st.Creds) > 0 || st.LoginEnvEpoch == "" {
		return
	}

	fileCks := readLinesFile(cookieFile)
	fileToks := readLinesFile(tokenOnlineFile)
	if len(fileCks) == 0 {
		return
	}

	migrated := 0
	_, err := lockAndModifyStore(func(s *StoreData) bool {
		if len(s.Creds) > 0 {
			return false // 另一个进程已经迁移过
		}
		creds := make(map[string]*Credential)
		for i, ck := range fileCks {
			mobile := mobileFromCookie(ck)
			if mobile == "" {
				continue
			}
			tok := ""
			if i < len(fileToks) {
				tok = fileToks[i]
			}
			envCk, envTok := envCredLine(i)
			creds[mobile] = &Credential{
				Mobile:      mobile,
				Cookie:      ck,
				TokenOnline: tok,
				// 用当前 env 行算指纹：旧版的接管状态等价于"env 行未变"，
				// 迁移后文件凭据继续生效，用户改 env 行即可夺回控制权
				EnvEpoch:  envCredFingerprint(envCk, envTok),
				UpdatedAt: time.Now().UnixMilli(),
			}
			migrated++
		}
		if migrated == 0 {
			return false
		}
		s.Creds = creds
		s.LoginEnvEpoch = "" // 迁移完成，旧字段退役
		return true
	})
	if err == nil && migrated > 0 {
		fmt.Printf("🔁 [凭据迁移] 已将 %d 个账号的轮换凭据迁入 store.Creds\n", migrated)
	}
}

// readLinesFile 按行读取非空行
func readLinesFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return splitCookieLines(string(data))
}

// splitCookieLines 按换行拆分并去空白（绝不按 & 拆，Cookie 内部本身就含 &）
func splitCookieLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(strings.Trim(l, "\r`"))
		if len(t) > 20 {
			out = append(out, t)
		}
	}
	return out
}

// saveCredential 在 flock 临界区内原子写入某手机号的轮换凭据。
// 凭据存进 store（而非独立的按行文本文件）有两个必要理由：
//   - 手机号索引不受账号顺序影响，换新 Cookie 也不会串号
//   - 与 store 共享同一把文件锁，多账号并行换新时不会互相覆盖
func saveCredential(mobile, cookie, token, envEpoch string) error {
	if mobile == "" {
		return fmt.Errorf("缺少手机号，拒绝写入凭据")
	}
	_, err := lockAndModifyStore(func(s *StoreData) bool {
		if s.Creds == nil {
			s.Creds = make(map[string]*Credential)
		}
		cred := s.Creds[mobile]
		if cred == nil {
			cred = &Credential{Mobile: mobile}
			s.Creds[mobile] = cred
		}
		cred.Cookie = cookie
		if token != "" {
			cred.TokenOnline = token
		}
		cred.EnvEpoch = envEpoch
		cred.UpdatedAt = time.Now().UnixMilli()

		// 同步 store.Cookies 中该账号所在行，供独立进程兜底读取
		for i, ck := range s.Cookies {
			if mobileFromCookie(ck) == mobile {
				s.Cookies[i] = cookie
				break
			}
		}
		return true
	})
	if err == nil {
		// 冗余落一份明文 Cookie 文件，兼容旧部署脚本与人工排查（失败不影响主流程）
		if st := loadStoreSafe(); st != nil && len(st.Cookies) > 0 {
			_ = writeFileAtomic(cookieFile, []byte(strings.Join(st.Cookies, "\n")), 0600)
		}
	}
	return err
}

// unicomLoginPost 发起联通手厅登录 POST，返回 (Set-Cookie 拼接, 响应 JSON, 错误)
func unicomLoginPost(loginURL string, form url.Values) (string, map[string]interface{}, error) {
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, fmt.Errorf("构建登录请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", unicomLoginUA)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("登录网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("登录网关异常 (HTTP %d)", resp.StatusCode)
	}

	// 拼接 Set-Cookie: 每条取 "name=value" 部分（丢弃 Domain/Path/Max-Age 等属性）
	var cookieParts []string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if i := strings.Index(c, ";"); i > 0 {
			c = c[:i]
		}
		if c != "" {
			cookieParts = append(cookieParts, c)
		}
	}
	newCookie := strings.Join(cookieParts, "; ")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newCookie, nil, fmt.Errorf("读取登录响应失败: %w", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return newCookie, nil, fmt.Errorf("解析登录响应失败: %w (body: %.200s)", err, string(body))
	}
	return newCookie, data, nil
}

// loginCodeOK 校验联通登录响应 code == "0"
func loginCodeOK(data map[string]interface{}) (bool, string) {
	if data == nil {
		return false, "响应为空"
	}
	code := ""
	switch v := data["code"].(type) {
	case string:
		code = v
	case float64:
		code = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if code != "0" {
		msg, _ := data["message"].(string)
		if msg == "" {
			msg, _ = data["msg"].(string)
		}
		return false, fmt.Sprintf("code=%s %s", code, msg)
	}
	return true, ""
}

// tokenOnlineLogin 使用 token_online 自动登录换新 Cookie（onLine.htm）
// 返回: 新Cookie, 新token_online(服务器轮换后), 有效期, 错误
func tokenOnlineLogin(tokenOnline string) (string, string, string, error) {
	if strings.TrimSpace(tokenOnline) == "" {
		return "", "", "", fmt.Errorf("token_online 未配置")
	}
	form := url.Values{}
	form.Set("appId", unicomAppID)
	form.Set("token_online", tokenOnline)
	form.Set("version", unicomAppVer)

	newCookie, data, err := unicomLoginPost(unicomOnlineURL, form)
	if err != nil {
		return "", "", "", err
	}
	if ok, why := loginCodeOK(data); !ok {
		return "", "", "", fmt.Errorf("TokenOnline 登录被拒绝: %s", why)
	}
	newToken, _ := data["token_online"].(string)
	invalidat, _ := data["invalidat"].(string)
	if newCookie == "" {
		return "", "", "", fmt.Errorf("登录成功但 Set-Cookie 为空")
	}
	return newCookie, newToken, invalidat, nil
}

// rsaEncryptUnicom 联通登录参数 RSA 加密（PKCS#1 v1.5, 输出 base64, 兼容 JSEncrypt）
func rsaEncryptUnicom(plain string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(unicomPubKeyB64)
	if err != nil {
		return "", fmt.Errorf("公钥解码失败: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("公钥解析失败: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("非 RSA 公钥")
	}
	enc, err := rsa.EncryptPKCS1v15(crand.Reader, pub, []byte(plain))
	if err != nil {
		return "", fmt.Errorf("RSA 加密失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// passwordLogin 使用手机号+服务密码登录换新 Cookie（login.htm, RSA 加密）
func passwordLogin(mobile, password string) (string, string, error) {
	if mobile == "" || password == "" {
		return "", "", fmt.Errorf("手机号/服务密码未配置")
	}
	encMobile, err := rsaEncryptUnicom(mobile)
	if err != nil {
		return "", "", err
	}
	encPwd, err := rsaEncryptUnicom(password)
	if err != nil {
		return "", "", err
	}
	form := url.Values{}
	form.Set("mobile", encMobile)
	form.Set("password", encPwd)
	form.Set("appId", unicomAppID)
	form.Set("version", unicomAppVer)

	newCookie, data, err := unicomLoginPost(unicomLoginURL, form)
	if err != nil {
		return "", "", err
	}
	if ok, why := loginCodeOK(data); !ok {
		return "", "", fmt.Errorf("密码登录被拒绝: %s", why)
	}
	newToken, _ := data["token_online"].(string)
	if newCookie == "" {
		return "", "", fmt.Errorf("登录成功但 Set-Cookie 为空")
	}
	return newCookie, newToken, nil
}

// autoRelogin Cookie 失效自愈编排: TokenOnline 优先 → 密码登录兜底。
//
// 成功后把新凭据按手机号写进 store.Creds（flock 保护），返回新 Cookie。
// 两条硬约束：
//   - 新 Cookie 的手机号必须与失效 Cookie 的手机号一致，否则拒绝持久化。
//     否则多账号场景下，全局单一的 mobile/password 配置会把账号 A 的 Cookie
//     写进账号 B 的槽位，让 B 的监控静默死亡而用户毫无感知。
//   - 密码兜底只在能确认归属时使用；无法确认手机号时不落盘。
func autoRelogin(idx int, oldCookie string) (string, bool) {
	oldMobile := mobileFromCookie(oldCookie)

	// 归属校验 + 持久化：登录换来的凭据必须属于这个账号
	persist := func(newCookie, newToken, envEpoch string) (string, bool) {
		newMobile := mobileFromCookie(newCookie)
		if oldMobile != "" && newMobile != "" && oldMobile != newMobile {
			fmt.Printf("⛔ [自动登录] 新 Cookie 归属账号与原账号不一致，拒绝写入（避免多账号串号）\n")
			return oldCookie, false
		}
		mobile := newMobile
		if mobile == "" {
			mobile = oldMobile
		}
		if mobile == "" {
			fmt.Println("⛔ [自动登录] 无法从 Cookie 中确认手机号，拒绝写入凭据")
			return oldCookie, false
		}
		if err := saveCredential(mobile, newCookie, newToken, envEpoch); err != nil {
			// 凭据落盘失败而 token 已被服务端轮换 = 旧 token 已作废且新 token 未保存，
			// 必须显式报错，否则下一轮会拿着废 token 反复失败且无迹可查
			fmt.Printf("❌ [自动登录] 新凭据写入失败: %v（新 token 可能已丢失，请检查存储可写性）\n", err)
			return oldCookie, false
		}
		return newCookie, true
	}

	st := loadStoreSafe()
	envCk, envTok := envCredLine(idx)
	envEpoch := envCredFingerprint(envCk, envTok)

	// 1. TokenOnline 自动登录（首选：无需明文密码，token 由服务端轮换）
	tok := tokenOnlineForAccount(st, oldMobile, idx)
	if tok != "" {
		fmt.Printf("🔄 [自动登录] 尝试 TokenOnline 登录 (账号 %d)...\n", idx+1)
		newCookie, newToken, invalidat, err := tokenOnlineLogin(tok)
		if err == nil {
			fmt.Printf("✅ [自动登录] TokenOnline 登录成功 (有效期: %s)，已换新 Cookie (%d 字节)\n",
				invalidat, len(newCookie))
			return persist(newCookie, newToken, envEpoch)
		}
		fmt.Printf("⚠️ [自动登录] TokenOnline 登录失败: %v\n", err)
	} else {
		fmt.Println("⚠️ [自动登录] 未配置 ChinaUnicom_10010v4_token_online，跳过 TokenOnline 登录")
	}

	// 2. 密码登录兜底
	mobile := strings.TrimSpace(getEnv("ChinaUnicom_10010v4_mobile", ""))
	password := strings.TrimSpace(getEnv("ChinaUnicom_10010v4_password", ""))
	if mobile != "" && password != "" {
		// mobile/password 是全局单值配置，与当前账号不符时必须跳过而不是照登
		if oldMobile != "" && mobile != oldMobile {
			fmt.Printf("⚠️ [自动登录] 已配置的密码账号与本账号不同，跳过密码兜底（避免串号）\n")
			return oldCookie, false
		}
		fmt.Printf("🔄 [自动登录] 尝试服务密码登录 (账号 %d)...\n", idx+1)
		newCookie, newToken, err := passwordLogin(mobile, password)
		if err == nil {
			fmt.Printf("✅ [自动登录] 密码登录成功，已换新 Cookie (%d 字节)\n", len(newCookie))
			return persist(newCookie, newToken, envEpoch)
		}
		fmt.Printf("⚠️ [自动登录] 密码登录失败: %v\n", err)
	}

	return oldCookie, false
}

// ======================== 消息推送客户端 ========================

// 从 Cookie 中提取手机号（c_mobile / u_account），作为跨 Cookie 轮换稳定的账号身份
var cookieMobileRe = regexp.MustCompile(`(?:c_mobile|u_account)=(\d{11})`)

func mobileFromCookie(cookie string) string {
	if m := cookieMobileRe.FindStringSubmatch(cookie); len(m) == 2 {
		return m[1]
	}
	return ""
}

// 账号稳定 key：优先用 Cookie 内的手机号指纹。
// 手机号在自动登录换新 Cookie 后保持不变，基线与历史不会因换 Cookie 而丢失；
// 取不到手机号时回落到 Cookie 全文指纹（旧行为）。
func accountKey(cookie string) string {
	if mobile := mobileFromCookie(cookie); mobile != "" {
		sum := md5.Sum([]byte("mobile:" + mobile))
		return "acc_" + hex.EncodeToString(sum[:])[:8]
	}
	return legacyCookieKey(cookie)
}

// legacyCookieKey 旧版账号 key：Cookie 全文指纹（换 Cookie 即漂移，仅用于迁移）
func legacyCookieKey(cookie string) string {
	sum := md5.Sum([]byte(cookie))
	return "acc_" + hex.EncodeToString(sum[:])[:8]
}

// pickLegacyAccount 在旧 key 候选中选出账号真身：历史最丰富、其次基线最新。
// 换 Cookie 会留下漂移副本，取"第一个命中"可能选到刚建立的空基线。
func pickLegacyAccount(store *StoreData, cookie string, idx int, exclude string) (string, *AccountStore) {
	bestKey := ""
	var best *AccountStore
	for _, ck := range []string{legacyCookieKey(cookie), fmt.Sprintf("acc_%d", idx)} {
		if ck == exclude {
			continue
		}
		old, ok := store.Accounts[ck]
		if !ok || old == nil {
			continue
		}
		if best == nil || len(old.History) > len(best.History) ||
			(len(old.History) == len(best.History) && old.LastTime > best.LastTime) {
			best, bestKey = old, ck
		}
	}
	return bestKey, best
}

// 兼容旧 key：从 Cookie 全文指纹 key 或 acc_N 下标 key 迁移到手机号 key。
func migrateLegacyAccountKey(store *StoreData, cookie string, idx int) string {
	key := accountKey(cookie)
	if _, ok := store.Accounts[key]; ok {
		return key
	}

	bestKey, best := pickLegacyAccount(store, cookie, idx, key)
	if best != nil {
		store.Accounts[key] = best
		delete(store.Accounts, bestKey)
		fmt.Printf("🔁 [账号 %d] 已迁移旧版存储 key %s -> %s (保留 %d 条历史)\n",
			idx+1, bestKey, key, len(best.History))
	}
	return key
}

func tgSend(method string, payload map[string]interface{}) bool {
	if tgBotToken == "" {
		return false
	}
	apiURL := fmt.Sprintf("%s/bot%s/%s", tgApiHost, tgBotToken, method)
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("❌ [TG 构建请求失败] %s: %v\n", method, err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("❌ [TG 网络异常] %s: %v\n", method, err)
		return false
	}
	defer resp.Body.Close()

	var res struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if !res.OK {
		fmt.Printf("❌ [TG API 拒绝] %s: %s\n", method, res.Description)
		return false
	}
	return true
}

func dingTalkURL() string {
	base := "https://oapi.dingtalk.com/robot/send?access_token=" + url.QueryEscape(ddBotToken)
	if ddBotSecret == "" {
		return base
	}

	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(ddBotSecret))
	mac.Write([]byte(ts + "\n" + ddBotSecret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return base + "&timestamp=" + ts + "&sign=" + url.QueryEscape(sign)
}

func sendDingTalk(title, content string) bool {
	if ddBotToken == "" {
		return false
	}

	fullText := fmt.Sprintf("%s\n%s", title, content)
	ddKeyword := getEnv("ChinaUnicom_10010v4_dd_keyword", getEnv("DD_BOT_KEYWORD", ""))
	if ddKeyword != "" && !strings.Contains(fullText, ddKeyword) {
		fullText = fmt.Sprintf("%s: %s", ddKeyword, fullText)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": fullText,
		},
	})

	resp, err := httpClient.Post(dingTalkURL(), "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("❌ [钉钉网络异常]: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("❌ [钉钉网关异常] HTTP %d\n", resp.StatusCode)
		return false
	}

	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res.ErrCode != 0 {
		fmt.Printf("❌ [钉钉拒收] 错误码: %d, 原因: %s\n", res.ErrCode, res.ErrMsg)
		return false
	}
	fmt.Println("✅ [钉钉] 已送达！")
	return true
}

func shouldSendDaidaiNotify() bool {
	// 1. 显式配置开关优先
	if getEnv("ENABLE_DAIDAI_NOTIFY", "0") == "1" {
		return true
	}
	// 2. 方案 B（智能兜底）：未配置专属 TG 且未配置专属钉钉时，若检测到处于呆呆面板环境，自动启用面板原生推送通道
	hasExclusiveChannel := (tgBotToken != "") || (ddBotToken != "")
	if !hasExclusiveChannel {
		hasDaidaiEnv := getEnv("DAIDAI_NOTIFY_URL", "") != "" || getEnv("DAIDAI_TOKEN", "") != "" || getEnv("DAIDAI_API_BASE", "") != ""
		return hasDaidaiEnv
	}
	return false
}

func sendDaidaiNotify(title, content string) bool {
	notifyURL := getEnv("DAIDAI_NOTIFY_URL", "")
	apiBase := getEnv("DAIDAI_API_BASE", "")
	token := getEnv("DAIDAI_TOKEN", "")
	if token == "" {
		token = getEnv("DAIDAI_NOTIFY_TOKEN", "")
	}

	if notifyURL == "" && apiBase != "" {
		notifyURL = strings.TrimRight(apiBase, "/") + "/notifications/send"
	}

	if notifyURL == "" || token == "" {
		return false
	}

	payload := map[string]interface{}{
		"title":   title,
		"content": content,
	}
	if chID := getEnv("DAIDAI_NOTIFY_CHANNEL_ID", ""); chID != "" {
		if id, err := strconv.Atoi(chID); err == nil && id > 0 {
			payload["channel_id"] = id
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", notifyURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("⚠️ [呆呆面板通知异常]: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Println("✅ [呆呆面板通知] 已成功投递至面板推送网关！")
		return true
	}

	fmt.Printf("⚠️ [呆呆面板通知失败] HTTP %d\n", resp.StatusCode)
	return false
}

func notifyFault(reason string) {
	now := time.Now().In(cst).UnixMilli()
	var shouldSend bool
	var owner string

	_, lockErr := lockAndModifyStore(func(s *StoreData) bool {
		if s.LastFaultAlertAt == 0 || (now-s.LastFaultAlertAt) > faultCooldown.Milliseconds() {
			s.LastFaultAlertAt = now
			shouldSend = true
		}
		owner = tgUserID
		if owner == "" {
			owner = s.OwnerID
		}
		return shouldSend
	})

	if lockErr != nil {
		// 抢不到锁/读盘失败时闭包没跑过，owner 仍为空。
		// 故障告警是最后一道通知，宁可无冷却重发也不能静默丢弃，
		// 因此这里必须自行补齐 owner（先 env，再只读兜底 store.OwnerID）。
		fmt.Printf("⚠️ [存储] 故障告警无法读写冷却状态 (%v)，改为无冷却直接发送\n", lockErr)
		shouldSend = true
		owner = tgUserID
		if owner == "" {
			if st := loadStoreSafe(); st != nil {
				owner = st.OwnerID
			}
		}
	}

	if !shouldSend {
		return
	}

	fmt.Println("🚨 [触发故障报警] 监控自身异常，推送通知！")
	title := "🚨 联通监控故障"
	body := fmt.Sprintf("%s\n\n请重新抓取 Cookie 并更新，否则跳点监控不会再有任何数据。\n时间：%s",
		reason, time.Now().In(cst).Format("2006-01-02 15:04:05"))

	if tgBotToken != "" && owner != "" {
		tgSend("sendMessage", map[string]interface{}{
			"chat_id":    owner,
			"text":       fmt.Sprintf("<b>%s</b>\n\n%s", html.EscapeString(title), html.EscapeString(body)),
			"parse_mode": "HTML",
		})
	}

	sendDingTalk(title, body)

	if shouldSendDaidaiNotify() {
		sendDaidaiNotify(title, body)
	}
}

// ======================== 核心数据查询与计算 ========================

// defaultFreeKeywords flowType 缺省时的免流判定关键词（可通过 ChinaUnicom_10010v4_free_keywords 追加）
var defaultFreeKeywords = []string{"免流", "定向", "直播", "畅视", "专享免费", "专属流量"}

func fetchAndCalculate(cookie string, accountIndex int, updateBaseline bool, diffMinutes int) (*QueryResult, error) {
	apiURL := "https://m.client.10010.com/servicequerybusiness/operationservice/queryOcsPackageFlowLeftContentRevisedInJune"

	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构建联通请求失败: %w", err)
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 14; 2211133C Build/UKQ1.230804.001);unicom{version:android@11.0900}")
	// 补齐 Header 防部分省份网关拦截
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("联通网关异常 (HTTP %d)", resp.StatusCode)
	}

	var data struct {
		Code        string `json:"code"`
		Message     string `json:"message"`
		PackageName string `json:"packageName"`
		Time        string `json:"time"`
		Resources   []struct {
			Type    string `json:"type"`
			Details []struct {
				FeePolicyName string      `json:"feePolicyName"`
				AddUpItemName string      `json:"addUpItemName"`
				Total         interface{} `json:"total"`
				Use           interface{} `json:"use"`
				Remain        interface{} `json:"remain"`
				Limited       interface{} `json:"limited"`
				FlowType      string      `json:"flowType"`
			} `json:"details"`
		} `json:"resources"`
	}

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		return nil, fmt.Errorf("读取联通响应失败: %w", readErr)
	}

	if err := json.Unmarshal(raw, &data); err != nil {
		// 只有"确实像会话失效"的响应才判 AuthError 去触发自动登录：
		// 裸错误码 999999、登录页 HTML、明文提示。
		// 把所有解析失败一律判成失效会在联通接口改版或返回网关错误页时
		// 反复消耗登录次数（token_online 每次登录都轮换，滥用有风控风险）。
		body := strings.TrimSpace(string(raw))
		peek := body
		if len(peek) > 200 {
			peek = peek[:200]
		}
		looksAuth := body == "999999" ||
			strings.Contains(body, "999999") ||
			strings.Contains(body, "登录") ||
			strings.Contains(strings.ToLower(body), "login")
		if looksAuth {
			return nil, &AuthError{Msg: fmt.Sprintf("联通接口返回会话失效响应: %s", peek)}
		}
		return nil, fmt.Errorf("联通接口响应无法解析 (可能接口改版或网关错误页): %s", peek)
	}

	if data.Code != "0000" {
		msg := fmt.Sprintf("联通接口异常 [%s]: %s", data.Code, data.Message)
		if len(data.Resources) == 0 {
			return nil, &AuthError{Msg: msg}
		}
		return nil, fmt.Errorf("%s", msg)
	}

	if len(data.Resources) == 0 {
		return nil, fmt.Errorf("联通接口返回空资源列表 (无套餐数据)")
	}

	var freeUnlimitUsed, freeLimitUsed, freeLimitTotal, freeLimitRemain float64
	var normUnlimitUsed, normLimitUsed, normLimitTotal, normLimitRemain float64
	var voiceTotal, voiceUsed, voiceRemain float64

	for _, res := range data.Resources {
		if res.Type == "flow" || res.Type == "MlFlowdetailsList" {
			for _, item := range res.Details {
				// 用分隔符拼接两个字段，避免关键词跨字段边界误命中
				// （如 "…套餐" + "免流…" 拼成 "套餐免流" 后被"餐免"之类的词组匹配）
				name := strings.TrimSpace(item.FeePolicyName) + " " + strings.TrimSpace(item.AddUpItemName)

				// 排除名单：命中的干扰项（如日租宝/赠款）不参与任何统计
				if len(excludeKeywords) > 0 && matchAnyKeyword(name, excludeKeywords) {
					if debugFlow {
						fmt.Printf("⏭️ [DEBUG-分流] 命中排除名单，跳过: %s\n", name)
					}
					continue
				}

				tot := toFloat(item.Total)
				u := toFloat(item.Use)
				rem := toFloat(item.Remain)

				// 无限量判定精细化：limited 字段显式存在时以其为准（1=无限量，0=有限量），
				// 仅当字段缺省时才退回"total<=0 视为无限量"的旧规则，杜绝 total 字段缺失被误判为无限量
				limitedVal, limitedPresent := toFloatPresence(item.Limited)
				isUnlimit := false
				if limitedPresent {
					isUnlimit = limitedVal == 1
				} else if tot <= 0 {
					isUnlimit = true
				}

				// 兜底：若接口未返回 remain 且非无限量，由 total - use 计算
				if rem <= 0 && tot > u && !isUnlimit {
					rem = tot - u
				}

				// 分流逻辑：以 flowType 为最高准则，杜绝整表误判通用流量
				var isFree bool
				if item.FlowType == "1" {
					isFree = false
				} else if item.FlowType == "2" || item.FlowType == "3" {
					isFree = true
				} else {
					// 当 flowType 缺省或未知时，由套餐名称特征深度判定（默认关键词 + 用户自定义关键词）
					isFree = matchAnyKeyword(name, defaultFreeKeywords) || matchAnyKeyword(name, freeKeywordsExtra)
				}

				if debugFlow {
					limitedStr := "缺省"
					if limitedPresent {
						limitedStr = strconv.FormatFloat(limitedVal, 'f', -1, 64)
					}
					fmt.Printf("🔍 [DEBUG-分流] 项: %s | flowType: %s | isFree: %v | isUnlimit: %v | limited: %s | tot: %.2f | use: %.2f | rem: %.2f\n",
						name, item.FlowType, isFree, isUnlimit, limitedStr, tot, u, rem)
				}

				if isFree {
					if isUnlimit {
						freeUnlimitUsed += u
					} else {
						freeLimitUsed += u
						freeLimitTotal += tot
						freeLimitRemain += rem
					}
				} else {
					if isUnlimit {
						normUnlimitUsed += u
					} else {
						normLimitUsed += u
						normLimitTotal += tot
						normLimitRemain += rem
					}
				}
			}
		}
		if res.Type == "Voice" {
			for _, item := range res.Details {
				tot := toFloat(item.Total)
				u := toFloat(item.Use)
				rem := toFloat(item.Remain)
				if rem <= 0 && tot > u {
					rem = tot - u
				}
				voiceTotal += tot
				voiceUsed += u
				voiceRemain += rem
			}
		}
	}

	freeTotal := freeLimitTotal
	freeUsed := freeUnlimitUsed + freeLimitUsed
	freeRemain := freeLimitRemain

	normTotal := normLimitTotal
	normUsed := normUnlimitUsed + normLimitUsed
	normRemain := normLimitRemain

	now := time.Now().In(cst)
	todayZero := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, cst).UnixMilli()
	// 账号 key 必须与监控周期写入时一致，否则主动查询（TG 按钮）会读到空基线，
	// 导致"今日用量恒为 0"与"永远首次记录"
	accKey := accountKey(cookie)

	currentSnap := &UsageSnapshot{
		FreeUnlimitedUsed: freeUnlimitUsed,
		FreeLimitedUsed:   freeLimitUsed,
		FreeUsed:          freeUsed,
		NormalLimitedUsed: normLimitUsed,
		NormalUsed:        normUsed,
	}

	var durationStr = "首次记录"
	var elapsedMinutes float64
	var diffNorm, diffNormLimit, diffFree, diffFreeUnlimit, diffFreeLimit float64
	var todayNorm, todayNormLimit, todayFree, todayFreeUnlimit, todayFreeLimit float64
	var surgeSkipped bool

	if updateBaseline {
		// ================= 守卫 3 & 4: 快照与基线只在监控周期写入 (单层锁保护) =================
		_, lockErr := lockAndModifyStore(func(store *StoreData) bool {
			accKey = migrateLegacyAccountKey(store, cookie, accountIndex)
			acc, ok := store.Accounts[accKey]
			if !ok {
				acc = &AccountStore{}
				store.Accounts[accKey] = acc
			}

			// 【防抖保护】：接口突发归零视为网关故障脏数据，拒绝刷乱基线。
			// 通用与免流两个池都要保护——免流池归零同样会毁掉基线，
			// 之后单轮增量虚高、今日用量失真。
			// 账期日前后 3 天放行真实归零（billingDay=31 在小月不存在，用范围判定而非等值）。
			inBillingWindow := now.Day() >= billingDay && now.Day()-billingDay < 3
			if !inBillingWindow && acc.Last != nil &&
				((acc.Last.NormalUsed > 10 && normUsed == 0) || (acc.Last.FreeUsed > 10 && freeUsed == 0)) {
				fmt.Println("⚠️ [防抖保护] 接口用量突发归零（疑似网关维护），本次放弃覆盖基线。")
				return false
			}

			// 【暴涨防抖】：单次增量异常大（疑似网关脏数据/翻倍错乱），首次静默一次不推送
			// 确认窗口内再次暴涨则判定为真实跳点，放行并清除可疑标记
			if surgeThreshold > 0 && acc.Last != nil && acc.LastTime > 0 {
				suspectNorm := normUsed >= acc.Last.NormalUsed && (normUsed-acc.Last.NormalUsed) > surgeThreshold
				suspectFree := freeUsed >= acc.Last.FreeUsed && (freeUsed-acc.Last.FreeUsed) > surgeThreshold
				if suspectNorm || suspectFree {
					if acc.LastSuspiciousTime == 0 || (now.Unix()-acc.LastSuspiciousTime) > surgeConfirmWindow {
						acc.LastSuspiciousTime = now.Unix()
						surgeSkipped = true
						fmt.Printf("⚠️ [暴涨防抖] 检测到疑似异常跳点 (通用+%.0fM / 免流+%.0fM)，本次静默并等待 %d 秒内二次确认。\n",
							normUsed-acc.Last.NormalUsed, freeUsed-acc.Last.FreeUsed, surgeConfirmWindow)
						// return true：仅持久化可疑标记并跳过本轮基线/历史更新（静默轮）
						return true
					}
					// 确认窗口内再次暴涨 → 真实跳点
					fmt.Println("🚨 [暴涨防抖] 确认窗口内再次出现异常跳点，判定为真实跳点，本次放行推送。")
					acc.LastSuspiciousTime = 0
				} else if acc.LastSuspiciousTime != 0 {
					// 恢复平静，清除可疑标记
					fmt.Println("✅ [暴涨防抖] 用量恢复正常，清除可疑标记。")
					acc.LastSuspiciousTime = 0
				}
			}

			// 守卫 5: ts 严格递增去重写入历史轨迹
			nowMs := now.UnixMilli()
			if len(acc.History) > 0 {
				lastTs := acc.History[len(acc.History)-1].Timestamp
				if nowMs <= lastTs {
					nowMs = lastTs + 1
				}
			}
			acc.History = append(acc.History, SnapshotRecord{
				Timestamp: nowMs,
				Snapshot:  currentSnap,
			})

			// 今日基线处理：仅跨天/首次时重置；同一天内用量倒退视为接口抖动，保留原基线。
			//
			// 必须在 trim 之前执行：跨天重置要回溯"昨天最后一条 ≤ 零点的快照"，
			// 而 trim 会按 historyKeepHours 删掉老记录（可低至 1 小时）。
			// 若先 trim，跨夜停机或 keepHours<24h 时零点基线会被删掉，
			// 基线退化成当前快照，凌晨到首检的真实消耗整段漏算。
			if acc.Today == nil || acc.TodayDate != todayZero {
				base := currentSnap
				if idx := lastSnapshotBeforeMs(acc.History, todayZero); idx >= 0 && acc.History[idx].Snapshot != nil {
					base = acc.History[idx].Snapshot
					fmt.Printf("🌅 [今日基线] 采用昨日最后快照 (%s) 作为零点基线，补齐凌晨空窗。\n",
						time.UnixMilli(acc.History[idx].Timestamp).In(cst).Format("01-02 15:04"))
				} else if len(acc.History) > 0 {
					fmt.Println("⚠️ [今日基线] 未找到零点前的历史快照（跨夜停机或保留时长过短），今日用量从本次开始计。")
				}
				acc.Today = base
				acc.TodayDate = todayZero
			}

			// 守卫 5: trim 只删超过保留时长（historyKeepHours，默认 24 小时）的最老记录
			oneDayAgo := now.Add(-time.Duration(historyKeepHours * float64(time.Hour))).UnixMilli()
			if len(acc.History) > 0 && acc.History[0].Timestamp < oneDayAgo {
				validIdx := 0
				for i, h := range acc.History {
					if h.Timestamp >= oneDayAgo {
						validIdx = i
						break
					}
				}
				if validIdx > 0 {
					acc.History = acc.History[validIdx:]
				}
			}

			todayNorm = normUsed - acc.Today.NormalUsed
			todayNormLimit = normLimitUsed - acc.Today.NormalLimitedUsed
			todayFree = freeUsed - acc.Today.FreeUsed
			todayFreeUnlimit = freeUnlimitUsed - acc.Today.FreeUnlimitedUsed
			todayFreeLimit = freeLimitUsed - acc.Today.FreeLimitedUsed

			if todayNorm < 0 {
				todayNorm = 0
			}
			if todayNormLimit < 0 {
				todayNormLimit = 0
			}
			if todayFree < 0 {
				todayFree = 0
			}
			if todayFreeUnlimit < 0 {
				todayFreeUnlimit = 0
			}
			if todayFreeLimit < 0 {
				todayFreeLimit = 0
			}

			if acc.Last != nil && acc.LastTime > 0 {
				elapsed := now.Sub(time.UnixMilli(acc.LastTime))
				durationStr = formatDuration(elapsed)
				elapsedMinutes = elapsed.Minutes()

				if normUsed >= acc.Last.NormalUsed {
					diffNorm = normUsed - acc.Last.NormalUsed
					diffNormLimit = normLimitUsed - acc.Last.NormalLimitedUsed
				}
				if freeUsed >= acc.Last.FreeUsed {
					diffFree = freeUsed - acc.Last.FreeUsed
					diffFreeUnlimit = freeUnlimitUsed - acc.Last.FreeUnlimitedUsed
					diffFreeLimit = freeLimitUsed - acc.Last.FreeLimitedUsed
				}
			}

			if diffNorm < 0 {
				diffNorm = 0
			}
			if diffNormLimit < 0 {
				diffNormLimit = 0
			}
			if diffFree < 0 {
				diffFree = 0
			}
			if diffFreeUnlimit < 0 {
				diffFreeUnlimit = 0
			}
			if diffFreeLimit < 0 {
				diffFreeLimit = 0
			}

			acc.Last = currentSnap
			acc.LastTime = now.UnixMilli()
			return true
		})

		if lockErr != nil {
			// 抢锁超时 → 闭包根本没执行，diffs 全为 0、durationStr 还是"首次记录"；
			// 落盘失败 → diffs 基于未持久化的基线，下一轮会重算同一段增量并重复推送。
			// 两种情况的结果都不可信，必须返回错误而不是交出半成品。
			return nil, fmt.Errorf("基线写入失败，本次跳点数据不可信: %w", lockErr)
		}
	} else {
		// ================= 守卫 2 & 3: 主动查询只读 loadStoreSafe，不写快照、不改基线与冷却 =================
		store := loadStoreSafe()
		acc, ok := store.Accounts[accKey]
		if !ok || acc == nil {
			// 只读兜底：手机号 key 尚未落盘时（首个监控周期还没跑），
			// 回退查旧 key。选取规则与 migrateLegacyAccountKey 一致（取历史最丰富的），
			// 否则升级后首次写入前可能展示较贫瘠的那份基线。
			if _, old := pickLegacyAccount(store, cookie, accountIndex, accKey); old != nil {
				acc = old
			}
		}
		if acc == nil {
			acc = &AccountStore{}
		}

		// 只读路径的今日基线：与写入分支口径对齐。
		// TodayDate 匹配时直接用已落盘的基线；不匹配（跨天后 cron 还没跑过，
		// 或 cron 已停摆）则临时回溯零点前的历史快照算出展示值——不落盘。
		// 否则 cron 挂掉时"今日用量"会整天显示 0.00M，而同屏还写着"距上次 5 小时"，
		// 自相矛盾且恰好误导用户排障。
		todayBase := acc.Today
		if acc.Today == nil || acc.TodayDate != todayZero {
			todayBase = nil
			if idx := lastSnapshotBeforeMs(acc.History, todayZero); idx >= 0 && acc.History[idx].Snapshot != nil {
				todayBase = acc.History[idx].Snapshot
			}
		}
		if todayBase != nil {
			todayNorm = normUsed - todayBase.NormalUsed
			todayNormLimit = normLimitUsed - todayBase.NormalLimitedUsed
			todayFree = freeUsed - todayBase.FreeUsed
			todayFreeUnlimit = freeUnlimitUsed - todayBase.FreeUnlimitedUsed
			todayFreeLimit = freeLimitUsed - todayBase.FreeLimitedUsed

			if todayNorm < 0 {
				todayNorm = 0
			}
			if todayNormLimit < 0 {
				todayNormLimit = 0
			}
			if todayFree < 0 {
				todayFree = 0
			}
			if todayFreeUnlimit < 0 {
				todayFreeUnlimit = 0
			}
			if todayFreeLimit < 0 {
				todayFreeLimit = 0
			}
		}

		effectiveMinutes := diffMinutes
		if effectiveMinutes < 0 {
			effectiveMinutes = 0
		}

		var baseSnap *UsageSnapshot
		var baseTime int64
		var isHistoryMatch bool

		// 守卫 5: 回溯取 <= 目标时间最大一条 (Floor 查找)，时间序永远单调一致
		if effectiveMinutes > 0 && len(acc.History) > 0 {
			targetTs := now.UnixMilli() - int64(effectiveMinutes)*60*1000
			var bestRecord *SnapshotRecord
			var isFloorFound bool

			for i := len(acc.History) - 1; i >= 0; i-- {
				if acc.History[i].Timestamp <= targetTs {
					bestRecord = &acc.History[i]
					isFloorFound = true
					break
				}
			}
			if bestRecord == nil {
				// 若历史快照均比 targetTs 新（例如刚启动不久，历史不足设定时长），取最老一条
				bestRecord = &acc.History[0]
				isFloorFound = false
			}

			if bestRecord != nil && bestRecord.Snapshot != nil {
				baseSnap = bestRecord.Snapshot
				baseTime = bestRecord.Timestamp
				isHistoryMatch = true

				elapsed := now.Sub(time.UnixMilli(baseTime))
				actualDurationStr := formatDuration(elapsed)
				actualSec := int64(elapsed.Seconds())
				targetSec := int64(effectiveMinutes * 60)

				// 只有当实际回溯时长与目标时长的误差在 90 秒内（正常巡检周期抖动）时，才视为精准匹配目标分钟数
				if isFloorFound && absInt64(actualSec-targetSec) <= 90 {
					durationStr = fmt.Sprintf("对比 %d分钟前 (基线 %s)", effectiveMinutes, time.UnixMilli(baseTime).In(cst).Format("15:04:05"))
				} else if isFloorFound {
					// 虽为 Floor 命中，但因接口限流/漏检导致实际回溯窗口与目标不一致（如查30分实际命中45分前）
					durationStr = fmt.Sprintf("对比 %s前 (目标%d分/基线 %s)", actualDurationStr, effectiveMinutes, time.UnixMilli(baseTime).In(cst).Format("15:04:05"))
				} else {
					// 历史快照总时长不足目标（如刚启动 8 分钟）
					durationStr = fmt.Sprintf("对比 %s前 (最老快照 %s)", actualDurationStr, time.UnixMilli(baseTime).In(cst).Format("15:04:05"))
				}
			}
		}

		if baseSnap == nil && acc.Last != nil && acc.LastTime > 0 {
			baseSnap = acc.Last
			baseTime = acc.LastTime
		}

		if baseSnap != nil && baseTime > 0 {
			elapsed := now.Sub(time.UnixMilli(baseTime))
			if !isHistoryMatch {
				durationStr = formatDuration(elapsed)
			}
			// 只读分支同样要给出 elapsedMinutes，否则 [通用速率]/[免流速率] 恒为占位符 "—"
			elapsedMinutes = elapsed.Minutes()

			if normUsed >= baseSnap.NormalUsed {
				diffNorm = normUsed - baseSnap.NormalUsed
				diffNormLimit = normLimitUsed - baseSnap.NormalLimitedUsed
			}
			if freeUsed >= baseSnap.FreeUsed {
				diffFree = freeUsed - baseSnap.FreeUsed
				diffFreeUnlimit = freeUnlimitUsed - baseSnap.FreeUnlimitedUsed
				diffFreeLimit = freeLimitUsed - baseSnap.FreeLimitedUsed
			}
		}

		if diffNorm < 0 {
			diffNorm = 0
		}
		if diffNormLimit < 0 {
			diffNormLimit = 0
		}
		if diffFree < 0 {
			diffFree = 0
		}
		if diffFreeUnlimit < 0 {
			diffFreeUnlimit = 0
		}
		if diffFreeLimit < 0 {
			diffFreeLimit = 0
		}
	}

	totalDiff := diffNorm + diffFree
	pkgName := data.PackageName
	if pkgName == "" {
		pkgName = "联通套餐"
	}

	vars := map[string]string{
		"[免流不限.已用]":   formatFlow(freeUnlimitUsed),
		"[免流不限.剩余]":   "不限",
		"[免流不限.总]":    "不限",
		"[免流不限.用量]":   formatFlow(diffFreeUnlimit),
		"[免流不限.今日用量]": formatFlow(todayFreeUnlimit),

		"[免流有限.已用]":   formatFlow(freeLimitUsed),
		"[免流有限.剩余]":   formatFlow(freeLimitRemain),
		"[免流有限.总]":    formatFlow(freeLimitTotal),
		"[免流有限.用量]":   formatFlow(diffFreeLimit),
		"[免流有限.今日用量]": formatFlow(todayFreeLimit),

		"[所有免流.已用]":   formatFlow(freeUsed),
		"[所有免流.剩余]":   formatFlow(freeRemain),
		"[所有免流.总]":    formatFlow(freeTotal),
		"[所有免流.用量]":   formatFlow(diffFree),
		"[所有免流.今日用量]": formatFlow(todayFree),

		"[通用有限.已用]":   formatFlow(normLimitUsed),
		"[通用有限.剩余]":   formatFlow(normLimitRemain),
		"[通用有限.总]":    formatFlow(normLimitTotal),
		"[通用有限.用量]":   formatFlow(diffNormLimit),
		"[通用有限.今日用量]": formatFlow(todayNormLimit),

		"[所有通用.已用]":   formatFlow(normUsed),
		"[所有通用.剩余]":   formatFlow(normRemain),
		"[所有通用.总]":    formatFlow(normTotal),
		"[所有通用.用量]":   formatFlow(diffNorm),
		"[所有通用.今日用量]": formatFlow(todayNorm),

		"[语音.总]":  fmt.Sprintf("%.0f分钟", voiceTotal),
		"[语音.已用]": fmt.Sprintf("%.0f分钟", voiceUsed),
		"[语音.剩余]": fmt.Sprintf("%.0f分钟", voiceRemain),

		"[套餐]":   pkgName,
		"[时长]":   durationStr,
		"[联通时间]": data.Time,
		"[时间]":   now.Format("15:04:05"),
		"[日期时间]": now.Format("2006-01-02 15:04:05"),
	}

	// 速率展示（MB/分钟），供 [通用速率]/[免流速率] 占位符使用
	normRateStr := "—"
	freeRateStr := "—"
	if elapsedMinutes > 0 {
		normRateStr = fmt.Sprintf("%s/分钟", formatFlow(diffNorm/elapsedMinutes))
		freeRateStr = fmt.Sprintf("%s/分钟", formatFlow(diffFree/elapsedMinutes))
	}
	vars["[通用速率]"] = normRateStr
	vars["[免流速率]"] = freeRateStr

	quote := getRandomQuote()
	vars["[随机语录]"] = quote
	vars["[一言]"] = quote
	vars["[语录]"] = quote

	defaultAutoTitle := "[套餐]"
	defaultAutoSubt := "[时长] 跳 [所有通用.用量] 免 [所有免流.用量]"
	defaultAutoDesc := "☸️通用总共 [通用有限.总] ✡️\n☯️通用已用 [通用有限.已用]🕎\n🕉️通用剩余 [通用有限.剩余] ☪️\n♒️免流已用 [所有免流.已用] ⛎\n🕉️今日通用 [所有通用.今日用量] 🕉️\n🕉️今日免流 [所有免流.今日用量] 🕉️\n♈️联通时间 [联通时间]♌️\n💌语录：[随机语录]"

	autoTitleTpl := getEnv("ChinaUnicom_10010v4_title", defaultAutoTitle)
	autoSubtTpl := getEnv("ChinaUnicom_10010v4_subt", defaultAutoSubt)
	autoDescTpl := getEnv("ChinaUnicom_10010v4_desc", defaultAutoDesc)

	autoTitle := renderTemplate(autoTitleTpl, vars)
	autoContent := fmt.Sprintf("%s\n%s", renderTemplate(autoSubtTpl, vars), renderTemplate(autoDescTpl, vars))

	escapedVars := make(map[string]string)
	for k, v := range vars {
		escapedVars[k] = v
	}
	escapedVars["[套餐]"] = html.EscapeString(pkgName)
	escapedVars["[联通时间]"] = html.EscapeString(data.Time)
	escapedVars["[随机语录]"] = html.EscapeString(quote)
	escapedVars["[一言]"] = html.EscapeString(quote)
	escapedVars["[语录]"] = html.EscapeString(quote)

	var defaultBotTitle string
	defaultBotDesc := "━━━━━━━━━━━━━━━━━━\n" +
		"📦 套餐：<b>[套餐]</b>\n" +
		"⏱ 距上次：<b>[时长]</b> ([时间])\n" +
		"━━━━━━━━━━━━━━━━━━\n" +
		"🚀 <b>本次跳点情况：</b>\n" +
		"• 通用跳点：<code>+[所有通用.用量]</code>\n" +
		"• 定向免流：<code>+[所有免流.用量]</code>\n" +
		"━━━━━━━━━━━━━━━━━━\n" +
		"📅 <b>今日累计消耗：</b>\n" +
		"• 今日通用：[所有通用.今日用量]\n" +
		"• 今日免流：[所有免流.今日用量]\n" +
		"━━━━━━━━━━━━━━━━━━\n" +
		"📊 <b>当前余量概览：</b>\n" +
		"• 通用剩余：[所有通用.剩余] (共 [所有通用.总])\n" +
		"• 免流已用：[所有免流.已用]\n" +
		"• 语音剩余：[语音.剩余]\n" +
		"━━━━━━━━━━━━━━━━━━\n" +
		"💬 <i>[随机语录]</i>\n" +
		"<i>联通时间: [联通时间]</i>"

	if diffMinutes == -1 {
		defaultBotTitle = "📦 <b>联通套餐总余量概览</b>"
		defaultBotDesc = "━━━━━━━━━━━━━━━━━━\n" +
			"📦 套餐：<b>[套餐]</b>\n" +
			"━━━━━━━━━━━━━━━━━━\n" +
			"📊 <b>当前余量概览：</b>\n" +
			"• 通用剩余：[所有通用.剩余] (共 [所有通用.总])\n" +
			"• 免流已用：[所有免流.已用]\n" +
			"• 语音剩余：[语音.剩余]\n" +
			"━━━━━━━━━━━━━━━━━━\n" +
			"📅 <b>今日累计消耗：</b>\n" +
			"• 今日通用：[所有通用.今日用量]\n" +
			"• 今日免流：[所有免流.今日用量]\n" +
			"━━━━━━━━━━━━━━━━━━\n" +
			"💬 <i>[随机语录]</i>\n" +
			"<i>联通时间: [联通时间]</i>"
	} else if !updateBaseline {
		if diffMinutes > 0 {
			defaultBotTitle = fmt.Sprintf("🔍 <b>联通跳点回溯查询 (%d分钟)</b>", diffMinutes)
		} else {
			defaultBotTitle = "⚡ <b>联通实时跳点查询</b>"
		}
	} else {
		defaultBotTitle = "⚡ <b>联通实时跳点播报</b>"
	}

	botTitleTpl := getEnv("ChinaUnicom_10010v4_bot_title", defaultBotTitle)
	botDescTpl := getEnv("ChinaUnicom_10010v4_bot_desc", defaultBotDesc)

	botContent := fmt.Sprintf("%s\n%s", renderTemplate(botTitleTpl, escapedVars), renderTemplate(botDescTpl, escapedVars))

	return &QueryResult{
		DurationStr:    durationStr,
		DiffNormal:     diffNorm,
		DiffFree:       diffFree,
		DiffNormLimit:  diffNormLimit,
		TotalDiffMb:    totalDiff,
		AutoTitle:      autoTitle,
		AutoContent:    autoContent,
		BotContent:     botContent,
		AccKey:         accKey,
		AccountIndex:   accountIndex,
		ElapsedMinutes: elapsedMinutes,
		SurgeSkipped:   surgeSkipped,
	}, nil
}

// ======================== PID 身份核对与抢占锁 ========================

func isPidOurDaemon(pid int) bool {
	if pid <= 0 || pid == os.Getpid() {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		// EPERM 表示进程活着但当前用户无权发信号（cron 与 daemon 不同用户时会出现），
		// 必须判为"存在"，否则会抢走运行中 daemon 的 pidfile
		if !errors.Is(err, syscall.EPERM) {
			return false
		}
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	s := strings.ReplaceAll(string(raw), "\x00", " ")
	return strings.Contains(s, filepath.Base(execSelf)) && strings.Contains(s, "--daemon")
}

func readPidFile() int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

// pidFileLock 在 daemon 整个生命周期内持有 pidFile 的 flock。
// 进程退出（含 os.Exit / 被 kill / 崩溃）时内核自动释放，因此不存在陈旧锁。
var pidFileLock *os.File

// claimPidFile 用 flock 而非 "O_EXCL 创建 + 读回校验" 做单例仲裁。
//
// O_EXCL 方案有一个真实的空窗：A 创建成功但还没写入 PID 时，B 的 O_EXCL 失败、
// 读到空文件（pid=0）→ 认为是僵尸文件 → 删掉 A 的文件并重建 → 两个 daemon 同时运行。
// flock 是内核级原子门槛，先抢锁后写 PID，没有这个窗口，也顺带免疫 PID 复用。
func claimPidFile() bool {
	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// 锁被持有 = 已有 daemon 在跑，无论文件内容是否陈旧
		_ = f.Close()
		return false
	}
	pidFileLock = f // 持锁到进程退出，不可关闭
	_ = f.Truncate(0)
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		pidFileLock = nil
		return false
	}
	_ = f.Sync()
	return true
}

func stopDaemon() {
	pid := readPidFile()
	if pid > 0 && isPidOurDaemon(pid) {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		_ = os.Remove(pidFile)
		fmt.Printf("🛑 [Go-v4x] 已关停守护进程 (PID: %d)\n", pid)
		return
	}
	_ = os.Remove(pidFile)
	fmt.Println("ℹ️ [Go-v4x] 当前没有运行中的守护进程")
}

// ======================== 后台 TG 响应协程 ========================

// jumpLabelRe 匹配底部快捷键盘「🔍 30分钟跳点」样式文本，跟随标签里的数字。
var jumpLabelRe = regexp.MustCompile(`^🔍\s*(\d+)\s*分钟跳点$`)

// buildTGInlineKeyboard 所有卡片统一的三键静态布局：
//
//	[⚡ 实时跳点] [🔍 N分钟跳点]
//	[📦 套餐总余量]
//
// ⚡ = 巡检查询（对比上次自动巡检，refresh_0）；🔍 = botDiffMinutes 分钟回溯；
// 📦 = 总余量。键盘不随卡片内容变化——任何卡片上都能一键跳到任一视图，
// 点当前视图的键即为刷新。accIdx 编进 callback_data，否则多账号时刷新
// 账号 2 的消息会显示账号 1 的数据。
func buildTGInlineKeyboard(accIdx int) map[string]interface{} {
	return map[string]interface{}{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": "⚡ 实时跳点", "callback_data": fmt.Sprintf("refresh_0_%d", accIdx)},
				{"text": fmt.Sprintf("🔍 %d分钟跳点", botDiffMinutes), "callback_data": fmt.Sprintf("refresh_%d_%d", botDiffMinutes, accIdx)},
			},
			{
				{"text": "📦 套餐总余量", "callback_data": fmt.Sprintf("refresh_-1_%d", accIdx)},
			},
		},
	}
}

// parseRefreshCallback 解析 refresh 回调，返回 (对比分钟数, 账号下标, 是否匹配)。
//
// 编码：refresh_0 = 巡检查询（⚡ 实时跳点）；refresh_<N> = N 分钟回溯；
// refresh_-1 = 总余量。旧格式 refresh_<分钟>（无下标）与 refresh_jump
// （最早期版本）都是巡检语义，直接按 0 处理。
// refresh_-2 是 8b207d7 过渡版的巡检回放键，同样映射回 0。
func parseRefreshCallback(data string) (int, int, bool) {
	if !strings.HasPrefix(data, "refresh_") {
		return 0, 0, false
	}
	body := strings.TrimPrefix(data, "refresh_")
	if body == "jump" {
		return 0, 0, true
	}
	parts := strings.Split(body, "_")
	min, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	if min == -2 {
		// 8b207d7 过渡版的巡检回放键 → 巡检
		min = 0
	}
	idx := 0
	if len(parts) >= 2 {
		if v, e := strconv.Atoi(parts[1]); e == nil && v >= 0 {
			idx = v
		}
	}
	return min, idx, true
}

func runTGDaemon() {
	if tgBotToken == "" {
		return
	}

	if !claimPidFile() {
		fmt.Println("ℹ️ [Go-v4x] 已有守护进程在运行，本次不重复启动")
		return
	}

	// 注册 Telegram 官方菜单指令（须与 /start 帮助文字、内联键盘保持同一套语义）。
	//
	// 必须重试：这一步只在守护进程启动时跑一次，反代抖动导致的一次 EOF
	// 会让指令菜单永久停留在上个版本的文案，而日志里只留一行网络异常，
	// 表现为"指令描述不对"这种看不出根因的故障。
	go func() {
		payload := map[string]interface{}{
			"commands": []map[string]string{
				{"command": "check", "description": "⚡ 实时跳点 (对比上次巡检)"},
				{"command": "total", "description": "📦 套餐总余量"},
				{"command": "diff", "description": fmt.Sprintf("🔍 跳点回溯 (默认 %d 分钟，如 /diff 60)", botDiffMinutes)},
				{"command": "help", "description": "💡 帮助与使用指南"},
			},
		}
		for attempt := 1; attempt <= 5; attempt++ {
			if tgSend("setMyCommands", payload) {
				if attempt > 1 {
					fmt.Printf("✅ [TG] 指令菜单注册成功 (第 %d 次尝试)\n", attempt)
				}
				return
			}
			if attempt < 5 {
				time.Sleep(time.Duration(attempt*3) * time.Second)
			}
		}
		fmt.Println("⚠️ [TG] 指令菜单注册连续 5 次失败，菜单可能仍是旧文案（不影响指令本身可用）")
	}()

	cleanup := func() {
		if readPidFile() == os.Getpid() {
			_ = os.Remove(pidFile)
		}
		os.Exit(0)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigChan
		cancel()
		cleanup()
	}()
	// 🌟 后台回环巡检引擎（默认关闭）。
	//
	// 与外部 Cron 同时驱动巡检是危险的，不只是"重复推送"：两个进程交替写基线，
	// 同一次真实跳点会被切成两半各自判定——真实 60M/3分、阈值 50M 时，
	// 两边各只看到 ~30M，增量与速率双双低于阈值，结果是永久静默。
	// 冷却能防重复，防不了这种稀释。所以只在不使用面板 Cron 时才开启此引擎。
	loopMin, _ := strconv.Atoi(getEnv("AUTO_CHECK_INTERVAL_MIN", "0"))
	if loopMin > 0 {
		if st := loadStoreSafe(); st != nil {
			for _, acc := range st.Accounts {
				// 外部 Cron 正在跑的判据：基线在 2 倍回环周期内被别的进程更新过
				if acc != nil && acc.LastTime > 0 &&
					time.Since(time.UnixMilli(acc.LastTime)) < time.Duration(loopMin*2)*time.Minute {
					fmt.Printf("⚠️ [配置冲突] 检测到近 %d 分钟内已有外部巡检写入基线，"+
						"内置回环引擎与面板 Cron 同时驱动会把跳点稀释到阈值以下而永久静默。"+
						"请二选一：关闭 AUTO_CHECK_INTERVAL_MIN 或停用面板 Cron。\n", loopMin*2)
					break
				}
			}
		}
		go func() {
			fmt.Printf("🔄 [Go-v4x] 启动后台回环巡检引擎 (每 %d 分钟巡检一次)\n", loopMin)
			ticker := time.NewTicker(time.Duration(loopMin) * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cks := getCookies()
					for idx, c := range cks {
						title := fmt.Sprintf("账号 %d", idx+1)
						r, err := fetchAndCalculate(c, idx, true, 0)
						if err == nil && r != nil {
							checkAndSendAlert(r, title)
						}
					}
				}
			}
		}()
	}

	store := loadStoreSafe()
	var offset int64 = 0
	if store != nil {
		offset = store.TGOffset
	}

	// bootstrapOffset 用 getUpdates?offset=-1 取最新 update_id 作为起点，丢弃积压。
	// 必须确认成功：失败后若带着 offset=0 进主循环，会把停机期间积压的所有旧命令
	// 全部重放一遍（历史"查跳点"被批量执行、消息刷屏）。
	bootstrapOffset := func() bool {
		reqURL := fmt.Sprintf("%s/bot%s/getUpdates?offset=-1&timeout=0", tgApiHost, tgBotToken)
		r, e := httpClient.Get(reqURL)
		if e != nil {
			return false
		}
		defer r.Body.Close()
		var ir struct {
			OK     bool `json:"ok"`
			Result []struct {
				UpdateID int64 `json:"update_id"`
			} `json:"result"`
		}
		if json.NewDecoder(r.Body).Decode(&ir) != nil || !ir.OK {
			return false
		}
		if len(ir.Result) > 0 {
			offset = ir.Result[len(ir.Result)-1].UpdateID + 1
			_, _ = lockAndModifyStore(func(s *StoreData) bool {
				s.TGOffset = offset
				return true
			})
		}
		// 队列为空也是有效结果：没有积压，offset 保持 0 即可
		return true
	}

	if offset == 0 {
		for attempt := 1; attempt <= 3; attempt++ {
			if bootstrapOffset() {
				break
			}
			fmt.Printf("⚠️ [TG] 第 %d 次获取起始 offset 失败，重试中...\n", attempt)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}

	lastSavedOffset := offset

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pollURL := fmt.Sprintf("%s/bot%s/getUpdates?offset=%d&timeout=30", tgApiHost, tgBotToken, offset)
		req, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		resp, err := tgPollClient.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		var updateData struct {
			OK          bool   `json:"ok"`
			ErrorCode   int    `json:"error_code"`
			Description string `json:"description"`
			Result      []struct {
				UpdateID int64 `json:"update_id"`
				Message  *struct {
					From *struct {
						ID    int64 `json:"id"`
						IsBot bool  `json:"is_bot"`
					} `json:"from"`
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
				CallbackQuery *struct {
					ID   string `json:"id"`
					Data string `json:"data"`
					From *struct {
						ID    int64 `json:"id"`
						IsBot bool  `json:"is_bot"`
					} `json:"from"`
					Message struct {
						MessageID int64 `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					} `json:"message"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		decodeErr := json.NewDecoder(resp.Body).Decode(&updateData)
		resp.Body.Close()

		// 【409 避让】：检测到多实例冲突时休眠避让，避免死循环打满 CPU
		if decodeErr != nil || !updateData.OK {
			if updateData.ErrorCode == 409 {
				fmt.Println("⚠️ [TG 轮询] 检测到 409 冲突（存在其他 Bot 实例在接收 updates），休眠 15 秒...")
				time.Sleep(15 * time.Second)
			} else {
				time.Sleep(2 * time.Second)
			}
			continue
		}

		for _, upd := range updateData.Result {
			if upd.UpdateID >= offset {
				offset = upd.UpdateID + 1
			}

			if upd.Message != nil {
				msg := upd.Message
				// 守卫 1: 自回复回环防御，忽略所有 Bot 发言
				if msg.From != nil && msg.From.IsBot {
					continue
				}

				chatID := strconv.FormatInt(msg.Chat.ID, 10)
				text := strings.TrimSpace(msg.Text)

				curStore := loadStoreSafe()
				owner := tgUserID
				if owner == "" {
					owner = curStore.OwnerID
				}

				if owner == "" && tgBindSecret != "" {
					if text == "/bind "+tgBindSecret {
						_, _ = lockAndModifyStore(func(s *StoreData) bool {
							s.OwnerID = chatID
							return true
						})
						tgSend("sendMessage", map[string]interface{}{
							"chat_id": chatID,
							"text":    "🎉 认主成功！当前设备已绑定至您的账号。",
						})
						continue
					}
				}

				// 守卫 1: 非白名单授权用户一律跳过
				if chatID != owner {
					continue
				}

				var isQueryCmd bool
				var queryMinutes int = 0

				if text == "/start" || text == "/help" {
					tgSend("sendMessage", map[string]interface{}{
						"chat_id": chatID,
						"text": "👋 <b>[Go-v4x] 联通监控在线！</b>\n\n" +
							"💡 <b>菜单功能指南：</b>\n" +
							"• <b>⚡ 实时跳点</b> (<code>/check</code>) : 对比<b>上次自动巡检</b>的实时跳点\n" +
							fmt.Sprintf("• <b>🔍 %d分钟跳点</b> (<code>/diff</code>) : 对比 <b>%d 分钟前</b>的用量\n", botDiffMinutes, botDiffMinutes) +
							"• <b>📦 套餐总余量</b> (<code>/total</code>) : 查看当前套餐余量与今日用量\n\n" +
							"💡 <b>回溯任意时长：</b>\n" +
							"• <code>/check 60</code>、<code>/diff 30</code> — 对比 N 分钟前的用量\n" +
							"• 亦可直接发送纯文字，例如 <code>5分钟</code>、<code>60分钟</code>\n\n" +
							"👇 点击下方菜单大按钮即可快速查询：",
						"parse_mode": "HTML",
						"reply_markup": map[string]interface{}{
							"keyboard": [][]map[string]string{
								{{"text": "⚡ 实时跳点"}, {"text": fmt.Sprintf("🔍 %d分钟跳点", botDiffMinutes)}},
								{{"text": "📦 套餐总余量"}},
							},
							"resize_keyboard": true,
						},
					})
				} else if text == "/check" || text == "⚡ 实时跳点" || text == "⚡ 实时查跳点" {
					// ⚡ = 巡检查询：对比上次自动巡检（约 3 分钟窗口）
					isQueryCmd = true
					queryMinutes = 0
				} else if text == "📦 套餐总余量" || text == "/total" {
					isQueryCmd = true
					queryMinutes = -1
				} else if text == "/diff" || text == "🔍 查询跳点" || text == "查询跳点" {
					isQueryCmd = true
					queryMinutes = botDiffMinutes
				} else if m := jumpLabelRe.FindStringSubmatch(text); m != nil {
					// 「🔍 30分钟跳点」样式（底部快捷键盘的第二键）：跟随标签里的数字
					if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
						isQueryCmd = true
						queryMinutes = n
					}
				} else if strings.HasPrefix(text, "/check") || strings.HasPrefix(text, "/diff") || strings.HasPrefix(text, "/查") {
					parts := strings.Fields(text)
					arg := ""
					if len(parts) >= 2 {
						arg = parts[1]
					}
					cleaned := strings.TrimSuffix(strings.TrimSuffix(arg, "分钟"), "m")
					m, err := strconv.Atoi(cleaned)
					switch {
					case err == nil && m == 0:
						// 显式 0 = 对比上次自动巡检（原「实时」语义的逃生舱）
						isQueryCmd = true
						queryMinutes = 0
					case err != nil || m < 0:
						// 参数无效必须明说：静默回落成其它窗口会让用户误判查的是什么
						tgSend("sendMessage", map[string]interface{}{
							"chat_id":    chatID,
							"text":       fmt.Sprintf("⚠️ 无法识别的时长参数 <code>%s</code>，请用非负整数分钟，例如 <code>/check 30</code>（<code>/check 0</code> = 对比上次巡检）", html.EscapeString(arg)),
							"parse_mode": "HTML",
						})
					default:
						isQueryCmd = true
						queryMinutes = m
					}
				} else if matched, _ := regexp.MatchString(`^\d+\s*(?:分钟|min|m)$`, text); matched {
					re := regexp.MustCompile(`\d+`)
					numStr := re.FindString(text)
					if m, err := strconv.Atoi(numStr); err == nil && m > 0 {
						isQueryCmd = true
						queryMinutes = m
					}
				}

				if isQueryCmd {
					cookies := getCookies()
					if len(cookies) == 0 {
						tgSend("sendMessage", map[string]interface{}{
							"chat_id": chatID,
							"text":    "⚠️ 未配置 Cookie！",
						})
					} else {
						nowMs := time.Now().In(cst).UnixMilli()

						// 冷却先于单飞锁检查：抢锁后再拒绝就必须手动回滚锁，
						// 任何一条提前 continue 都会把机器人永久卡在"正在查询中"
						lastTime := atomic.LoadInt64(&lastManualQueryAt)
						if lastTime > 0 && (nowMs-lastTime) < manualCooldownSec*1000 {
							remainSec := manualCooldownSec - (nowMs-lastTime)/1000
							tgSend("sendMessage", map[string]interface{}{
								"chat_id":    chatID,
								"text":       fmt.Sprintf("⚡ 刚刚才查过，请 <b>%d</b> 秒后再试~", remainSec),
								"parse_mode": "HTML",
							})
							continue
						}

						if !atomic.CompareAndSwapInt32(&isQueryingAtomic, 0, 1) {
							tgSend("sendMessage", map[string]interface{}{
								"chat_id": chatID,
								"text":    "⏳ 正在查询中，请勿重复点击...",
							})
							continue
						}

						atomic.StoreInt64(&lastManualQueryAt, nowMs)

						go func(cks []string, cid string, qMin int) {
							defer atomic.StoreInt32(&isQueryingAtomic, 0)
							for i, c := range cks {
								accTitle := fmt.Sprintf("账号 %d", i+1)
								res, err := fetchAndCalculate(c, i, false, qMin)
								if err != nil {
									tgSend("sendMessage", map[string]interface{}{
										"chat_id": cid,
										"text":    fmt.Sprintf("❌ [%s] 查询失败: %s", accTitle, html.EscapeString(err.Error())),
									})
								} else {
									content := res.BotContent
									if len(cks) > 1 {
										content = fmt.Sprintf("👤 <b>[%s]</b>\n%s", accTitle, content)
									}
									tgSend("sendMessage", map[string]interface{}{
										"chat_id":      cid,
										"text":         content,
										"parse_mode":   "HTML",
										"reply_markup": buildTGInlineKeyboard(i),
									})
								}
							}
						}(cookies, chatID, queryMinutes)
					}
				}
			}

			if upd.CallbackQuery != nil {
				cq := upd.CallbackQuery
				// 守卫 1: 忽略所有 Bot 点击回调
				if cq.From != nil && cq.From.IsBot {
					continue
				}

				chatID := strconv.FormatInt(cq.Message.Chat.ID, 10)
				curStore := loadStoreSafe()
				owner := tgUserID
				if owner == "" {
					owner = curStore.OwnerID
				}

				qMin, accIdx, isRefresh := parseRefreshCallback(cq.Data)
				if chatID == owner && isRefresh {
					nowMs := time.Now().In(cst).UnixMilli()

					// 冷却先于单飞锁检查：抢锁后再拒绝就必须手动回滚锁，
					// 任何一条提前 continue 都会把机器人永久卡在"正在查询中"
					lastTime := atomic.LoadInt64(&lastManualQueryAt)
					if lastTime > 0 && (nowMs-lastTime) < manualCooldownSec*1000 {
						remainSec := manualCooldownSec - (nowMs-lastTime)/1000
						tgSend("answerCallbackQuery", map[string]interface{}{
							"callback_query_id": cq.ID,
							"text":              fmt.Sprintf("⚡ 刚刚才查过，请 %d 秒后再试~", remainSec),
						})
						continue
					}

					if !atomic.CompareAndSwapInt32(&isQueryingAtomic, 0, 1) {
						tgSend("answerCallbackQuery", map[string]interface{}{
							"callback_query_id": cq.ID,
							"text":              "⏳ 正在查询中，请勿重复点击...",
						})
						continue
					}

					atomic.StoreInt64(&lastManualQueryAt, nowMs)

					hint := "正在对比上次巡检消耗..."
					if qMin > 0 {
						hint = fmt.Sprintf("正在对比 %d 分钟前消耗...", qMin)
					} else if qMin == -1 {
						hint = "正在查询套餐总余量..."
					}
					tgSend("answerCallbackQuery", map[string]interface{}{
						"callback_query_id": cq.ID,
						"text":              hint,
					})

					cookies := getCookies()
					if len(cookies) > 0 {
						// 回调必须刷新按钮所属的那个账号：callback_data 里带了下标，
						// 越界（账号数变少）时回落 0
						if accIdx >= len(cookies) {
							accIdx = 0
						}
						multi := len(cookies) > 1
						go func(c string, cid string, reqMin, idx int) {
							defer atomic.StoreInt32(&isQueryingAtomic, 0)
							accTitle := fmt.Sprintf("账号 %d", idx+1)
							res, err := fetchAndCalculate(c, idx, false, reqMin)
							body := ""
							if err != nil {
								// 失败也要给出反馈：否则看着像卡死
								body = fmt.Sprintf("❌ [%s] 查询失败: %s", accTitle, html.EscapeString(err.Error()))
							} else {
								body = res.BotContent
								if multi {
									body = fmt.Sprintf("👤 <b>[%s]</b>\n%s", accTitle, body)
								}
							}
							// 点按钮 = 发一条新消息（不再原地编辑旧卡片），
							// 每次查询都在对话里留下独立记录，方便回溯对比
							tgSend("sendMessage", map[string]interface{}{
								"chat_id":      cid,
								"text":         body,
								"parse_mode":   "HTML",
								"reply_markup": buildTGInlineKeyboard(idx),
							})
						}(cookies[accIdx], chatID, qMin, accIdx)
					} else {
						atomic.StoreInt32(&isQueryingAtomic, 0)
					}
				}
			}
		}

		if offset != lastSavedOffset {
			_, _ = lockAndModifyStore(func(s *StoreData) bool {
				s.TGOffset = offset
				return true
			})
			lastSavedOffset = offset
			if store != nil {
				store.TGOffset = offset
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// ======================== 告警判定与精准推送 ========================

func checkAndSendAlert(res *QueryResult, accTitle string) {
	if res == nil {
		return
	}

	// 【暴涨防抖】静默轮只记录基线、不推送
	if res.SurgeSkipped {
		fmt.Printf("⚠️ [%s] 本次为暴涨防抖静默轮，跳过推送。\n", accTitle)
		return
	}

	// 双独立阈值判定（增量 + 速率双条件，速率按 rateWindowMinutes 窗口归一）
	// 判定口径：normalLimitedOnly=1 时通用通道改用"通用有限池"增量，
	// 排除不限量池（如专属不限量包）对通用跳点的稀释/虚增，展示口径保持不变
	diffNormJudge := res.DiffNormal
	normLabel := "通用跳点"
	normRateLabel := "通用速率"
	if normalLimitedOnly {
		diffNormJudge = res.DiffNormLimit
		normLabel = "通用跳点(有限池)"
		normRateLabel = "通用速率(有限池)"
	}
	rateNorm := 0.0
	rateFree := 0.0
	if res.ElapsedMinutes > 0 {
		rateNorm = diffNormJudge / res.ElapsedMinutes * rateWindowMinutes
		rateFree = res.DiffFree / res.ElapsedMinutes * rateWindowMinutes
	}
	isNormTriggered := minNormUsage > 0 && (diffNormJudge >= minNormUsage || rateNorm >= minNormUsage)
	isFreeTriggered := minFreeUsage > 0 && (res.DiffFree >= minFreeUsage || rateFree >= minFreeUsage)

	// 越级放行仅针对通用流量
	isBypass := alertBypassMb > 0 && diffNormJudge >= alertBypassMb

	// 免流显著加大越级：冷却期内若跳点 ≥ 阈值×3，视为"显著加大"，允许再次推送
	freeSurgePass := minFreeUsage > 0 && res.DiffFree >= minFreeUsage*3

	var allowSend bool
	var normPassed, freePassed bool
	var triggerReasons []string
	now := time.Now().In(cst).UnixMilli()
	// 记录被覆盖前的冷却时间戳，三通道全部发送失败时用于回滚，
	// 避免"告警丢了、冷却却已消耗"——监控工具最不能接受的双重失效
	var prevAlertNorm, prevAlertFree int64
	var cooldownWritten bool

	_, lockErr := lockAndModifyStore(func(s *StoreData) bool {
		acc := s.Accounts[res.AccKey]
		if acc == nil {
			return false
		}

		// 兼容老版本单字段平滑升级
		if acc.LastAlertNorm == 0 && acc.LastAlertTime > 0 {
			acc.LastAlertNorm = acc.LastAlertTime
		}
		prevAlertNorm, prevAlertFree = acc.LastAlertNorm, acc.LastAlertFree

		// 1. 通用跳点判定
		if isNormTriggered {
			if isBypass || alertCooldown <= 0 || acc.LastAlertNorm == 0 || (now-acc.LastAlertNorm) >= alertCooldown.Milliseconds() {
				normPassed = true
				acc.LastAlertNorm = now
				reason := fmt.Sprintf("%s +%s >= %s", normLabel, formatFlow(diffNormJudge), formatFlow(minNormUsage))
				if diffNormJudge < minNormUsage && rateNorm >= minNormUsage {
					// 左右两边必须同口径：阈值是"每窗口"，所以速率也要换算成每窗口，
					// 否则会打出"16.67M ≥ 50M/3分"这种左小于右的自相矛盾文案
					reason = fmt.Sprintf("%s %s ≥ %s/%.0f分", normRateLabel, formatFlow(rateNorm), formatFlow(minNormUsage), rateWindowMinutes)
				}
				if isBypass {
					reason += " [越级放行]"
				}
				triggerReasons = append(triggerReasons, reason)
			} else {
				fmt.Printf("⏳ [%s] %s已达标 (+%s)，但在冷却期内 (%s)，跳过该项推送\n",
					accTitle, normLabel, formatFlow(diffNormJudge), cooldownText(alertCooldown))
			}
		}

		// 2. 免流跳点判定（独立通道、独立冷却；显著加大可越级）
		if isFreeTriggered {
			if freeSurgePass || freeAlertCooldown <= 0 || acc.LastAlertFree == 0 || (now-acc.LastAlertFree) >= freeAlertCooldown.Milliseconds() {
				freePassed = true
				acc.LastAlertFree = now
				reason := fmt.Sprintf("免流跳点 +%s >= %s", formatFlow(res.DiffFree), formatFlow(minFreeUsage))
				if res.DiffFree < minFreeUsage && rateFree >= minFreeUsage {
					reason = fmt.Sprintf("免流速率 %s ≥ %s/%.0f分", formatFlow(rateFree), formatFlow(minFreeUsage), rateWindowMinutes)
				} else if freeSurgePass {
					reason += " [显著加大越级]"
				}
				triggerReasons = append(triggerReasons, reason)
			} else {
				fmt.Printf("⏳ [%s] 免流跳点已达标 (+%s)，但在免流冷却期内 (%s)，跳过该项推送\n",
					accTitle, formatFlow(res.DiffFree), cooldownText(freeAlertCooldown))
			}
		}

		allowSend = normPassed || freePassed
		cooldownWritten = allowSend
		return allowSend
	})

	if errors.Is(lockErr, ErrAcquireLockTimeout) {
		fmt.Println("⚠️ [存储] 抢锁超时，告警降级为无冷却强制发送！")
		normPassed = isNormTriggered
		freePassed = isFreeTriggered
		allowSend = isNormTriggered || isFreeTriggered
		if isNormTriggered {
			triggerReasons = append(triggerReasons, fmt.Sprintf("%s +%s [抢锁超时强制放行]", normLabel, formatFlow(diffNormJudge)))
		}
		if isFreeTriggered {
			triggerReasons = append(triggerReasons, fmt.Sprintf("免流跳点 +%s [抢锁超时强制放行]", formatFlow(res.DiffFree)))
		}
	}

	if allowSend {
		var prefix string
		if normPassed && freePassed {
			prefix = "🟡 [混合] "
		} else if normPassed {
			prefix = "🔴 [跳点] "
		} else if freePassed {
			prefix = "🟢 [免流] "
		}

		finalAutoTitle := res.AutoTitle
		finalAutoContent := prefix + res.AutoContent
		// 状态前缀直接前插：不能只替换默认标题字面量，
		// 否则用户自定义了 bot_title 后 🔴/🟡/🟢 前缀会静默消失
		finalBotContent := res.BotContent
		if prefix != "" {
			if strings.HasPrefix(finalBotContent, "⚡ <b>联通实时跳点播报</b>") {
				finalBotContent = strings.Replace(finalBotContent,
					"⚡ <b>联通实时跳点播报</b>", prefix+"<b>联通实时跳点播报</b>", 1)
			} else {
				finalBotContent = prefix + finalBotContent
			}
		}

		fmt.Printf("🚀 [%s] 触发报警 (%s)，发送通知！\n", accTitle, strings.Join(triggerReasons, " | "))

		store := loadStoreSafe()
		owner := tgUserID
		if owner == "" {
			owner = store.OwnerID
		}
		useTG := tgBotToken != "" && owner != ""
		useDaidai := shouldSendDaidaiNotify()
		anyConfigured := ddBotToken != "" || useTG || useDaidai

		anySent := sendDingTalk(finalAutoTitle, finalAutoContent)
		if useTG {
			if tgSend("sendMessage", map[string]interface{}{
				"chat_id": owner,
				"text":    finalBotContent,
				// 自动播报卡片同样挂统一三键键盘，随时可跳转到任一视图
				"parse_mode":   "HTML",
				"reply_markup": buildTGInlineKeyboard(res.AccountIndex),
			}) {
				anySent = true
			}
		}
		if useDaidai {
			if sendDaidaiNotify(finalAutoTitle, finalAutoContent) {
				anySent = true
			}
		}

		// 已配置通道但全部失败 → 回滚冷却时间戳，让下一轮可以补报。
		// 未配置任何通道时不回滚：那是用户主动选择静默，不是发送故障。
		if anyConfigured && !anySent && cooldownWritten {
			fmt.Println("⚠️ [推送] 所有通道均发送失败，回滚冷却时间戳以便下轮补报")
			_, _ = lockAndModifyStore(func(s *StoreData) bool {
				acc := s.Accounts[res.AccKey]
				if acc == nil {
					return false
				}
				if normPassed && acc.LastAlertNorm == now {
					acc.LastAlertNorm = prevAlertNorm
				}
				if freePassed && acc.LastAlertFree == now {
					acc.LastAlertFree = prevAlertFree
				}
				return true
			})
		}
	} else if !isNormTriggered && !isFreeTriggered {
		fmt.Printf("⏳ [%s] 本次%s(+%s / 阈值 %s)与免流(+%s / 阈值 %s)均未达标，静默不扰。\n",
			accTitle, normLabel,
			formatFlow(diffNormJudge), thresholdText(minNormUsage),
			formatFlow(res.DiffFree), thresholdText(minFreeUsage))
	}
}

// ======================== 主入口 (多账号轮询 + 三色前缀精准推送) ========================

func main() {
	// 升级路径：旧版凭据在独立文本文件里，必须先迁进 store.Creds 再做任何登录判定
	migrateLegacyCreds()

	if len(os.Args) > 1 {
		if os.Args[1] == "stop" || os.Args[1] == "--stop" {
			stopDaemon()
			os.Exit(0)
		}
		if os.Args[1] == "--daemon" {
			runTGDaemon()
			os.Exit(0)
		}
	}

	if tgBotToken != "" {
		pid := readPidFile()
		if !isPidOurDaemon(pid) {
			logPath := filepath.Join(scriptDir, "10010v4x_daemon.log")

			flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
			if fi, err := os.Stat(logPath); err == nil && fi.Size() > 2*1024*1024 {
				flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
			}

			logF, err := os.OpenFile(logPath, flag, 0644)
			// 🌟 彻底摘除管道：显式绑定独立日志文件或 /dev/null，严禁继承父进程 stdout/stderr/stdin 管道
			// 避免面板因为等不到管道 EOF 导致任务永远卡在「运行中」及后续写入已关闭管道触发 SIGPIPE 暴毙
			devNull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			cmd := exec.Command(execSelf, "--daemon")
			cmd.Stdin = devNull

			if err == nil && logF != nil {
				cmd.Stdout = logF
				cmd.Stderr = logF
			} else {
				cmd.Stdout = devNull
				cmd.Stderr = devNull
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := cmd.Start(); err == nil {
				_ = cmd.Process.Release()
			}
			if logF != nil {
				_ = logF.Close()
			}
			if devNull != nil {
				_ = devNull.Close()
			}
		}
		if tgBindSecret == "" && tgUserID == "" && loadStoreSafe().OwnerID == "" {
			fmt.Println("⚠️ [安全] 未设 TG_USER_ID / TG_BIND_SECRET：当前已禁止任何陌生人自动认主")
		}
	}

	cookies := getCookies()
	if len(cookies) == 0 {
		fmt.Println("⚠️ [v4x] 未检测到有效 Cookie，请检查配置！")
		notifyFault("未检测到有效 Cookie")
		os.Exit(1)
	}

	if minNormUsage <= 0 && minFreeUsage <= 0 {
		fmt.Println("⚠️ [配置] 通用与免流跳点阈值均为 0，报警已关闭（只记录基线、不推送）")
	}

	// 🌟 多账号支持：并行轮询每个 Cookie（互不阻塞）
	var wg sync.WaitGroup
	maxConsecutiveFailures, _ := strconv.Atoi(getEnv("ChinaUnicom_10010v4_max_failures", "3"))
	if maxConsecutiveFailures <= 0 {
		maxConsecutiveFailures = 3
	}

	for idx, cookie := range cookies {
		wg.Add(1)
		go func(idx int, cookie string) {
			defer wg.Done()
			accTitle := fmt.Sprintf("账号 %d", idx+1)
			fmt.Printf("\n========== 🚀 开始检测 [%s] ==========\n", accTitle)

			res, err := fetchAndCalculate(cookie, idx, true, 0)
			if err != nil {
				var authErr *AuthError
				if errors.As(err, &authErr) {
					// 【自动登录自愈】Cookie 失效时先尝试自动登录换新，成功则用新 Cookie 重试本次巡检
					fmt.Printf("❌ [%s] Cookie 已失效: %s\n", accTitle, authErr.Msg)
					fmt.Printf("🔄 [%s] 尝试自动登录换新 Cookie...\n", accTitle)
					if newCookie, ok := autoRelogin(idx, cookie); ok {
						if r2, e2 := fetchAndCalculate(newCookie, idx, true, 0); e2 == nil {
							fmt.Printf("✅ [%s] 自动登录成功，本次巡检已用新 Cookie 恢复。\n", accTitle)
							res, err = r2, nil
						} else {
							fmt.Printf("⚠️ [%s] 已换新 Cookie 但查询仍失败: %v\n", accTitle, e2)
							err = e2
						}
					}
				}
			}

			if err != nil {
				fmt.Printf("❌ [%s] 查询异常: %v\n", accTitle, err)

				var authErr *AuthError
				if errors.As(err, &authErr) {
					notifyFault(fmt.Sprintf("[%s] Cookie 已失效且自动登录失败: %s", accTitle, authErr.Msg))
					// 认证失败走独立的 notifyFault 通道，只清本账号的网络失败计数
					recordFailStreak(cookie, idx, false, 0, accTitle)
				} else {
					fmt.Printf("ℹ️ [%s] 为网络/网关临时波动 (非 Cookie 失效)，保持静默。\n", accTitle)
					recordFailStreak(cookie, idx, true, maxConsecutiveFailures, accTitle)
				}
				return
			}

			// 查询成功：清零本账号的连续失败计数
			recordFailStreak(cookie, idx, false, 0, accTitle)

			fmt.Println("\n============== 📣 [v4x] 自动报警模版预览 📣 ==============")
			fmt.Printf("【%s】\n%s\n", res.AutoTitle, res.AutoContent)
			fmt.Println("==========================================================")
			fmt.Printf("⏱ 距上次检测: %s | 本次合计跳点: +%s (通用+%s, 免流+%s)\n",
				res.DurationStr, formatFlow(res.TotalDiffMb), formatFlow(res.DiffNormal), formatFlow(res.DiffFree))

			checkAndSendAlert(res, accTitle)
		}(idx, cookie)
	}

	wg.Wait()

	os.Exit(0)
}

// failStreakResetSec 超过这个时长没有新的失败，计数视为过期并重置。
// 取 6 小时：足够跨过一段持续故障，又不会让隔天的偶发失败累加成误报。
const failStreakResetSec = 6 * 3600

// recordFailStreak 按账号累计/清零"连续非认证失败"次数，并在达阈值时告警一次。
//
// 计数必须落在 store（而非进程变量）：巡检进程由 cron 每 3 分钟重新拉起，
// 进程内计数每次都从 0 开始，"连续 N 次失败"这条安全网实际上永远不会触发。
// 计数按账号隔离，避免健康账号把故障账号的累计清零、掩盖真实故障。
func recordFailStreak(cookie string, idx int, isFailure bool, threshold int, accTitle string) {
	nowSec := time.Now().Unix()
	var alertAt int

	_, err := lockAndModifyStore(func(s *StoreData) bool {
		key := migrateLegacyAccountKey(s, cookie, idx)
		acc := s.Accounts[key]
		if acc == nil {
			acc = &AccountStore{}
			s.Accounts[key] = acc
		}

		if !isFailure {
			if acc.FailStreak == 0 && acc.FailStreakAt == 0 {
				return false
			}
			acc.FailStreak = 0
			acc.FailStreakAt = 0
			return true
		}

		// 上次失败太久以前 → 不算"连续"，重新起算
		if acc.FailStreakAt > 0 && nowSec-acc.FailStreakAt > failStreakResetSec {
			acc.FailStreak = 0
		}
		acc.FailStreak++
		acc.FailStreakAt = nowSec

		if threshold > 0 && acc.FailStreak >= threshold {
			alertAt = acc.FailStreak
			acc.FailStreak = 0
			acc.FailStreakAt = 0
		}
		return true
	})
	if err != nil {
		fmt.Printf("⚠️ [%s] 失败计数写入失败: %v\n", accTitle, err)
		return
	}

	// 告警在锁外发送，避免持锁期间做网络请求
	if alertAt > 0 {
		notifyFault(fmt.Sprintf("[%s] 连续 %d 次巡检查询失败（非 Cookie 失效），可能联通接口变更或网络故障",
			accTitle, alertAt))
	}
}
