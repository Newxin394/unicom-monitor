package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
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
}

type StoreData struct {
	Accounts         map[string]*AccountStore `json:"accounts"`
	OwnerID          string                   `json:"ownerId"`
	TGOffset         int64                    `json:"tgOffset"`
	LastFaultAlertAt int64                    `json:"lastFaultAlertAt"`
	Cookies          []string                 `json:"cookies,omitempty"`
}

type QueryResult struct {
	PackageName string
	DurationStr string
	DiffNormal  float64
	DiffFree    float64
	TotalDiffMb float64
	AutoTitle   string
	AutoContent string
	BotContent  string
	AccKey      string
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

	tgBotToken   string
	tgUserID     string
	tgApiHost    string
	tgBindSecret string
	ddBotToken   string
	ddBotSecret  string // 钉钉「加签」密钥，SEC 开头

	minNormUsage float64 // 通用流量跳点阈值，默认 50M
	minFreeUsage float64 // 免流流量跳点阈值，默认 400M

	botDiffMinutes    int           // 机器人主动查询默认对比时长（分钟），默认 0（对比上次自动巡检）
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
	if envDir := getEnv("DAIDAI_SCRIPTS_DIR", ""); envDir != "" {
		scriptDir = envDir
	} else if qlDir := getEnv("QL_DIR", ""); qlDir != "" {
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

	// 清理历史崩溃遗留的 .tmp 中间文件
	if matches, _ := filepath.Glob(dataFile + ".*.tmp"); len(matches) > 0 {
		for _, p := range matches {
			_ = os.Remove(p)
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

	// 机器人默认独立对比时长（分钟），默认 30 分钟
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
	freeCdSec, _ := strconv.Atoi(getEnv("ChinaUnicom_10010v4_free_cooldown", "1800"))
	if freeCdSec < 0 {
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
	if st, _ := strconv.ParseFloat(getEnv("ChinaUnicom_10010v4_surge_threshold_mb", "1024"), 64); st >= 0 {
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

// 占位符按长度降序替换，防止 [所有通用.用量] 被 [所有通用.用] 短键截胡
func renderTemplate(tpl string, vars map[string]string) string {
	res := strings.ReplaceAll(tpl, "\\n", "\n")

	type kv struct {
		k string
		v string
	}
	pairs := make([]kv, 0, len(vars))
	for k, v := range vars {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].k) > len(pairs[j].k)
	})

	for _, p := range pairs {
		res = strings.ReplaceAll(res, p.k, p.v)
	}
	return res
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

	store := loadStoreSafe()

	if !updater(store) {
		return store, nil
	}

	tmpFile := fmt.Sprintf("%s.%d.%d.tmp", dataFile, os.Getpid(), time.Now().UnixNano())
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(tmpFile, raw, 0644); err != nil {
		return nil, err
	}

	// 只在主数据本身健康时才刷新 .bak
	if storeMainHealthy.Load() {
		if oldRaw, err := os.ReadFile(dataFile); err == nil {
			var check StoreData
			if json.Unmarshal(oldRaw, &check) == nil && check.Accounts != nil {
				_ = os.WriteFile(bakFile, oldRaw, 0644)
			}
		}
	}

	if err := os.Rename(tmpFile, dataFile); err != nil {
		_ = os.Remove(tmpFile)
		return nil, err
	}
	storeMainHealthy.Store(true)

	return store, nil
}

func loadStoreSafe() *StoreData {
	store := &StoreData{Accounts: make(map[string]*AccountStore)}
	storeMainHealthy.Store(true)

	if raw, err := os.ReadFile(dataFile); err == nil {
		if json.Unmarshal(raw, store) == nil {
			if store.Accounts == nil {
				store.Accounts = make(map[string]*AccountStore)
			}
			return store
		}
	}

	storeMainHealthy.Store(false)
	fmt.Println("⚠️ [存储] 主数据损坏，尝试用 .bak 恢复...")

	store = &StoreData{Accounts: make(map[string]*AccountStore)}
	if bakRaw, err := os.ReadFile(bakFile); err == nil {
		if json.Unmarshal(bakRaw, store) == nil {
			if store.Accounts == nil {
				store.Accounts = make(map[string]*AccountStore)
			}
			fmt.Println("✅ [存储] 已从 .bak 找回基线数据")
			return store
		}
	}

	return store
}

// 只按换行拆分 Cookie，绝不按 & 拆（Cookie 内部本身就含 &）
func getCookies() []string {
	cookieStr := getEnv("UNICOM_COOKIE", getEnv("ChinaUnicom_10010v4_cookie", ""))
	if cookieStr == "" {
		if data, err := os.ReadFile(cookieFile); err == nil {
			cookieStr = strings.TrimSpace(string(data))
		}
	}
	if cookieStr == "" {
		// 从持久化存储兜底读取，确保独立 daemon 进程在空 env 下依然可用
		st := loadStoreSafe()
		if st != nil && len(st.Cookies) > 0 {
			return st.Cookies
		}
		return nil
	}

	var list []string
	for _, l := range strings.Split(cookieStr, "\n") {
		trimmed := strings.TrimSpace(strings.Trim(l, "\r`"))
		if len(trimmed) > 20 {
			list = append(list, trimmed)
		}
	}

	// 自动持久化落盘，确保守护进程跨进程共享 Cookie
	if len(list) > 0 {
		_ = os.WriteFile(cookieFile, []byte(strings.Join(list, "\n")), 0600)
		_, _ = lockAndModifyStore(func(s *StoreData) bool {
			if len(s.Cookies) != len(list) {
				s.Cookies = list
				return true
			}
			return false
		})
	}

	return list
}

// ======================== 消息推送客户端 ========================

// 账号稳定 key：用 Cookie 内容指纹，避免多账号因 Cookie 顺序变化导致基线串号
func accountKey(cookie string, idx int) string {
	sum := md5.Sum([]byte(cookie))
	return "acc_" + hex.EncodeToString(sum[:])[:8]
}

// 兼容旧版 acc_N 下标 key：同 Cookie 找到旧条目则迁移到指纹 key
func migrateLegacyAccountKey(store *StoreData, cookie string, idx int) string {
	key := accountKey(cookie, idx)
	if _, ok := store.Accounts[key]; ok {
		return key
	}
	legacyKey := fmt.Sprintf("acc_%d", idx)
	if old, ok := store.Accounts[legacyKey]; ok {
		store.Accounts[key] = old
		delete(store.Accounts, legacyKey)
		fmt.Printf("🔁 [账号 %d] 已迁移旧版存储 key -> %s\n", idx+1, key)
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

	if errors.Is(lockErr, ErrAcquireLockTimeout) {
		fmt.Println("⚠️ [存储] 抢锁超时，故障告警改为无冷却直接发送")
		shouldSend = true
		if owner == "" {
			owner = tgUserID
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

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("解析联通响应失败: %w", err)
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
				name := item.FeePolicyName + item.AddUpItemName

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
	accKey := fmt.Sprintf("acc_%d", accountIndex)

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

			// 【防抖保护】：非账期日且之前已有正常用量，但接口突发归零，视为网关故障脏数据，拒绝刷乱基线
			if now.Day() != billingDay && acc.Last != nil && acc.Last.NormalUsed > 10 && normUsed == 0 {
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

			// 今日基线处理：仅跨天/首次时重置；同一天内用量倒退视为接口抖动，保留原基线
			if acc.Today == nil || acc.TodayDate != todayZero {
				// 跨天重置时优先回溯"昨天最后一条历史快照"作零点基线，
				// 补齐任务在 00:00 空窗期未运行导致的今日用量少算（漏掉凌晨消耗）
				base := currentSnap
				if idx := lastSnapshotBeforeMs(acc.History, todayZero); idx >= 0 && acc.History[idx].Snapshot != nil {
					base = acc.History[idx].Snapshot
					fmt.Printf("🌅 [今日基线] 采用昨日最后快照 (%s) 作为零点基线，补齐凌晨空窗。\n",
						time.UnixMilli(acc.History[idx].Timestamp).In(cst).Format("01-02 15:04"))
				}
				acc.Today = base
				acc.TodayDate = todayZero
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
			fmt.Printf("⚠️ [存储] 本次基线写入失败 (%v)，跳点数据不可信\n", lockErr)
		}
	} else {
		// ================= 守卫 2 & 3: 主动查询只读 loadStoreSafe，不写快照、不改基线与冷却 =================
		store := loadStoreSafe()
		acc, ok := store.Accounts[accKey]
		if !ok || acc == nil {
			acc = &AccountStore{}
		}

		if acc.Today != nil && acc.TodayDate == todayZero {
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
		PackageName:    pkgName,
		DurationStr:    durationStr,
		DiffNormal:     diffNorm,
		DiffFree:       diffFree,
		DiffNormLimit:  diffNormLimit,
		TotalDiffMb:    totalDiff,
		AutoTitle:      autoTitle,
		AutoContent:    autoContent,
		BotContent:     botContent,
		AccKey:         accKey,
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
		return false
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

func claimPidFile() bool {
	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
		f.Close()
		return true
	}

	oldPid := readPidFile()
	if oldPid > 0 && oldPid != os.Getpid() && isPidOurDaemon(oldPid) {
		return false
	}

	_ = os.Remove(pidFile)
	fRetry, errRetry := os.OpenFile(pidFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if errRetry == nil {
		_, _ = fRetry.WriteString(strconv.Itoa(os.Getpid()))
		fRetry.Close()
		return true
	}
	return false
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

func buildTGInlineKeyboard(diffMin int) map[string]interface{} {
	refreshLabel := "🔄 刷新当前"
	if diffMin > 0 {
		refreshLabel = fmt.Sprintf("🔄 刷新 (%d分钟)", diffMin)
	} else if diffMin == -1 {
		refreshLabel = "🔄 刷新总余量"
	} else if botDiffMinutes > 0 {
		refreshLabel = fmt.Sprintf("🔄 刷新 (%d分钟)", botDiffMinutes)
	}
	botMin := botDiffMinutes
	if botMin <= 0 {
		botMin = 30
	}
	return map[string]interface{}{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": refreshLabel, "callback_data": fmt.Sprintf("refresh_%d", diffMin)},
				{"text": "⚡ 实时跳点", "callback_data": "refresh_0"},
			},
			{
				{"text": fmt.Sprintf("🔍 查询跳点 (%d分)", botMin), "callback_data": fmt.Sprintf("refresh_%d", botMin)},
				{"text": "📦 套餐总余量", "callback_data": "refresh_-1"},
			},
			{
				{"text": "⏱ 5分钟", "callback_data": "refresh_5"},
				{"text": "⏱ 10分钟", "callback_data": "refresh_10"},
				{"text": "⏱ 30分钟", "callback_data": "refresh_30"},
			},
		},
	}
}

func runTGDaemon() {
	if tgBotToken == "" {
		return
	}

	if !claimPidFile() {
		fmt.Println("ℹ️ [Go-v4x] 已有守护进程在运行，本次不重复启动")
		return
	}

	// 注册 Telegram 官方菜单指令
	tgSend("setMyCommands", map[string]interface{}{
		"commands": []map[string]string{
			{"command": "check", "description": "⚡ 实时跳点 (对比上次自动巡检)"},
			{"command": "diff", "description": "🔍 查询跳点 (回溯独立时长)"},
			{"command": "total", "description": "📦 套餐总余量"},
			{"command": "help", "description": "💡 帮助与使用指南"},
		},
	})

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
	// 🌟 后台回环巡检引擎（默认关闭，避免与面板 Cron 双循环重复推送）
	// 推荐由外部 Cron（*/3 分钟）统一驱动巡检与告警；仅当不使用面板 Cron 时才开启此引擎
	// 可通过 AUTO_CHECK_INTERVAL_MIN 显式开启（如 3）
	loopMin, _ := strconv.Atoi(getEnv("AUTO_CHECK_INTERVAL_MIN", "0"))
	if loopMin > 0 {
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

	if offset == 0 {
		reqURL := fmt.Sprintf("%s/bot%s/getUpdates?offset=-1&timeout=0", tgApiHost, tgBotToken)
		if r, e := httpClient.Get(reqURL); e == nil {
			var ir struct {
				OK     bool `json:"ok"`
				Result []struct {
					UpdateID int64 `json:"update_id"`
				} `json:"result"`
			}
			if json.NewDecoder(r.Body).Decode(&ir) == nil && len(ir.Result) > 0 {
				offset = ir.Result[len(ir.Result)-1].UpdateID + 1
				_, _ = lockAndModifyStore(func(s *StoreData) bool {
					s.TGOffset = offset
					return true
				})
				if store != nil {
					store.TGOffset = offset
				}
			}
			r.Body.Close()
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
							"• <b>⚡ 实时跳点</b> (<code>/check</code>) : 对比上次自动巡检的实时跳点\n" +
							"• <b>🔍 查询跳点</b> (<code>/diff</code>) : 回溯独立时长（如 5 分钟）对比差值\n" +
							"• <b>📦 套餐总余量</b> (<code>/total</code>) : 查看当前套餐余量与今日用量\n\n" +
							"💡 <b>高级指令：</b>\n" +
							"• 可随时输入指定分钟数，如 <code>/check 10</code>、<code>/check 30</code>\n" +
							"• 亦可直接发送纯文字，例如 <code>5分钟</code>、<code>10分钟</code>\n\n" +
							"👇 点击下方菜单大按钮即可快速查询：",
						"parse_mode": "HTML",
						"reply_markup": map[string]interface{}{
							"keyboard": [][]map[string]string{
								{{"text": "⚡ 实时跳点"}, {"text": "🔍 查询跳点"}},
								{{"text": "📦 套餐总余量"}},
							},
							"resize_keyboard": true,
						},
					})
				} else if text == "/check" || text == "⚡ 实时跳点" || text == "⚡ 实时查跳点" {
					isQueryCmd = true
					queryMinutes = 0
				} else if text == "/diff" || text == "🔍 查询跳点" || text == "查询跳点" {
					isQueryCmd = true
					if botDiffMinutes > 0 {
						queryMinutes = botDiffMinutes
					} else {
						queryMinutes = 30
					}
				} else if text == "📦 套餐总余量" || text == "/total" {
					isQueryCmd = true
					queryMinutes = -1
				} else if text == "⏱ 查5分钟跳点" || text == "5分钟" || text == "5m" {
					isQueryCmd = true
					queryMinutes = 5
				} else if text == "⏱ 查10分钟跳点" || text == "10分钟" || text == "10m" {
					isQueryCmd = true
					queryMinutes = 10
				} else if strings.HasPrefix(text, "/check") || strings.HasPrefix(text, "/diff") || strings.HasPrefix(text, "/查") {
					parts := strings.Fields(text)
					isQueryCmd = true
					if len(parts) >= 2 {
						cleaned := strings.TrimSuffix(strings.TrimSuffix(parts[1], "分钟"), "m")
						if m, err := strconv.Atoi(cleaned); err == nil && m > 0 {
							queryMinutes = m
						}
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
						if !atomic.CompareAndSwapInt32(&isQueryingAtomic, 0, 1) {
							tgSend("sendMessage", map[string]interface{}{
								"chat_id": chatID,
								"text":    "⏳ 正在查询中，请勿重复点击...",
							})
							continue
						}

						lastTime := atomic.LoadInt64(&lastManualQueryAt)
						if lastTime > 0 && (nowMs-lastTime) < manualCooldownSec*1000 {
							remainSec := manualCooldownSec - (nowMs-lastTime)/1000
							atomic.StoreInt32(&isQueryingAtomic, 0)
							tgSend("sendMessage", map[string]interface{}{
								"chat_id":    chatID,
								"text":       fmt.Sprintf("⚡ 刚刚才查过，请 <b>%d</b> 秒后再试~", remainSec),
								"parse_mode": "HTML",
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
										"reply_markup": buildTGInlineKeyboard(qMin),
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

				if chatID == owner && (cq.Data == "refresh_jump" || strings.HasPrefix(cq.Data, "refresh_")) {
					qMin := 0
					if strings.HasPrefix(cq.Data, "refresh_") {
						mStr := strings.TrimPrefix(cq.Data, "refresh_")
						if m, err := strconv.Atoi(mStr); err == nil {
							qMin = m
						}
					}

					nowMs := time.Now().In(cst).UnixMilli()

					if !atomic.CompareAndSwapInt32(&isQueryingAtomic, 0, 1) {
						tgSend("answerCallbackQuery", map[string]interface{}{
							"callback_query_id": cq.ID,
							"text":              "⏳ 正在查询中，请勿重复点击...",
						})
						continue
					}

					lastTime := atomic.LoadInt64(&lastManualQueryAt)
					if lastTime > 0 && (nowMs-lastTime) < manualCooldownSec*1000 {
						remainSec := manualCooldownSec - (nowMs-lastTime)/1000
						atomic.StoreInt32(&isQueryingAtomic, 0)
						tgSend("answerCallbackQuery", map[string]interface{}{
							"callback_query_id": cq.ID,
							"text":              fmt.Sprintf("⚡ 刚刚才查过，请 %d 秒后再试~", remainSec),
						})
						continue
					}

					atomic.StoreInt64(&lastManualQueryAt, nowMs)

					hint := "正在查询最新跳点..."
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
						go func(c string, cid string, msgID int64, reqMin int) {
							defer atomic.StoreInt32(&isQueryingAtomic, 0)
							res, err := fetchAndCalculate(c, 0, false, reqMin)
							if err == nil {
								tgSend("editMessageText", map[string]interface{}{
									"chat_id":      cid,
									"message_id":   msgID,
									"text":         res.BotContent,
									"parse_mode":   "HTML",
									"reply_markup": buildTGInlineKeyboard(reqMin),
								})
							}
						}(cookies[0], chatID, cq.Message.MessageID, qMin)
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

	_, lockErr := lockAndModifyStore(func(s *StoreData) bool {
		acc := s.Accounts[res.AccKey]
		if acc == nil {
			return false
		}

		// 兼容老版本单字段平滑升级
		if acc.LastAlertNorm == 0 && acc.LastAlertTime > 0 {
			acc.LastAlertNorm = acc.LastAlertTime
		}

		// 1. 通用跳点判定
		if isNormTriggered {
			if isBypass || alertCooldown <= 0 || acc.LastAlertNorm == 0 || (now-acc.LastAlertNorm) >= alertCooldown.Milliseconds() {
				normPassed = true
				acc.LastAlertNorm = now
				reason := fmt.Sprintf("%s +%s >= %s", normLabel, formatFlow(diffNormJudge), formatFlow(minNormUsage))
				if diffNormJudge < minNormUsage && rateNorm >= minNormUsage {
					reason = fmt.Sprintf("%s %s ≥ %s/%.0f分", normRateLabel, formatFlow(diffNormJudge/res.ElapsedMinutes), formatFlow(minNormUsage), rateWindowMinutes)
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
					reason = fmt.Sprintf("免流速率 %s ≥ %s/%.0f分", formatFlow(res.DiffFree/res.ElapsedMinutes), formatFlow(minFreeUsage), rateWindowMinutes)
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
		finalBotContent := strings.Replace(
			res.BotContent,
			"⚡ <b>联通实时跳点播报</b>",
			prefix+"<b>联通实时跳点播报</b>",
			1,
		)

		fmt.Printf("🚀 [%s] 触发报警 (%s)，发送通知！\n", accTitle, strings.Join(triggerReasons, " | "))
		sendDingTalk(finalAutoTitle, finalAutoContent)

		store := loadStoreSafe()
		owner := tgUserID
		if owner == "" {
			owner = store.OwnerID
		}

		if tgBotToken != "" && owner != "" {
			tgSend("sendMessage", map[string]interface{}{
				"chat_id":      owner,
				"text":         finalBotContent,
				"parse_mode":   "HTML",
				"reply_markup": buildTGInlineKeyboard(0),
			})
		}

		if shouldSendDaidaiNotify() {
			sendDaidaiNotify(finalAutoTitle, finalAutoContent)
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

	// 🌟 多账号支持：并行轮询每个 Cookie（互不阻塞），并统计连续非认证失败次数
	// 连续失败（非 Cookie 失效）≥3 次时触发一次故障告警，防真故障无感知
	var wg sync.WaitGroup
	var failMu sync.Mutex
	consecutiveFailures := 0
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
				fmt.Printf("❌ [%s] 查询异常: %v\n", accTitle, err)

				var authErr *AuthError
				if errors.As(err, &authErr) {
					notifyFault(fmt.Sprintf("[%s] Cookie 已失效: %s", accTitle, authErr.Msg))
					failMu.Lock()
					consecutiveFailures = 0
					failMu.Unlock()
				} else {
					fmt.Printf("ℹ️ [%s] 为网络/网关临时波动 (非 Cookie 失效)，保持静默。\n", accTitle)
					failMu.Lock()
					consecutiveFailures++
					if consecutiveFailures >= maxConsecutiveFailures {
						notifyFault(fmt.Sprintf("连续 %d 次巡检查询失败（非 Cookie 失效），可能联通接口变更或网络故障", consecutiveFailures))
						consecutiveFailures = 0
					}
					failMu.Unlock()
				}
				return
			}

			// 查询成功即清零连续失败计数
			failMu.Lock()
			consecutiveFailures = 0
			failMu.Unlock()

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
