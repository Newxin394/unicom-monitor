package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
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
		scriptDir = "."
	} else {
		scriptDir = filepath.Dir(execSelf)
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

	body, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": fmt.Sprintf("%s\n\n%s", title, content),
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
}

// ======================== 核心数据查询与计算 ========================

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
				tot := toFloat(item.Total)
				u := toFloat(item.Use)
				rem := toFloat(item.Remain)
				isUnlimit := toFloat(item.Limited) == 1 || tot <= 0

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
					// 当 flowType 缺省或未知时，由套餐名称特征深度判定
					isFree = strings.Contains(name, "免流") || strings.Contains(name, "定向") ||
						strings.Contains(name, "直播") || strings.Contains(name, "畅视") ||
						strings.Contains(name, "专享免费") || strings.Contains(name, "专属流量")
				}

				if getEnv("ChinaUnicom_10010v4_debug", "0") == "1" {
					fmt.Printf("🔍 [DEBUG-分流] 项: %s | flowType: %s | isFree: %v | isUnlimit: %v | tot: %.2f | use: %.2f | rem: %.2f\n",
						name, item.FlowType, isFree, isUnlimit, tot, u, rem)
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
	var diffNorm, diffNormLimit, diffFree, diffFreeUnlimit, diffFreeLimit float64
	var todayNorm, todayNormLimit, todayFree, todayFreeUnlimit, todayFreeLimit float64

	if updateBaseline {
		// ================= 守卫 3 & 4: 快照与基线只在监控周期写入 (单层锁保护) =================
		_, lockErr := lockAndModifyStore(func(store *StoreData) bool {
			acc, ok := store.Accounts[accKey]
			if !ok {
				acc = &AccountStore{}
				store.Accounts[accKey] = acc
			}

			// 【防抖保护】：非 1 号且之前已有正常用量，但接口突发归零，视为网关故障脏数据，拒绝刷乱基线
			if now.Day() != 1 && acc.Last != nil && acc.Last.NormalUsed > 10 && normUsed == 0 {
				fmt.Println("⚠️ [防抖保护] 接口用量突发归零（疑似网关维护），本次放弃覆盖基线。")
				return false
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

			// 守卫 5: trim 只删超过 24 小时的最老记录
			oneDayAgo := now.Add(-24 * time.Hour).UnixMilli()
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

			// 今日基线处理
			if acc.Today == nil || acc.TodayDate != todayZero || normUsed < acc.Today.NormalUsed {
				acc.Today = currentSnap
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
		if effectiveMinutes == 0 && botDiffMinutes > 0 {
			effectiveMinutes = botDiffMinutes
		}
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
			var isExactFloor bool

			for i := len(acc.History) - 1; i >= 0; i-- {
				if acc.History[i].Timestamp <= targetTs {
					bestRecord = &acc.History[i]
					isExactFloor = true
					break
				}
			}
			if bestRecord == nil {
				bestRecord = &acc.History[0]
				isExactFloor = false
			}

			if bestRecord != nil && bestRecord.Snapshot != nil {
				baseSnap = bestRecord.Snapshot
				baseTime = bestRecord.Timestamp
				isHistoryMatch = true
				if isExactFloor {
					durationStr = fmt.Sprintf("对比 %d分钟前 (基线 %s)", effectiveMinutes, time.UnixMilli(baseTime).In(cst).Format("15:04:05"))
				} else {
					elapsed := now.Sub(time.UnixMilli(baseTime))
					durationStr = fmt.Sprintf("对比 %s (最老快照 %s)", formatDuration(elapsed), time.UnixMilli(baseTime).In(cst).Format("15:04:05"))
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

		"[语音.总]":    fmt.Sprintf("%.0f分钟", voiceTotal),
		"[语音.已用]":   fmt.Sprintf("%.0f分钟", voiceUsed),
		"[语音.剩余]":   fmt.Sprintf("%.0f分钟", voiceRemain),

		"[套餐]":   pkgName,
		"[时长]":   durationStr,
		"[联通时间]": data.Time,
		"[时间]":   now.Format("15:04:05"),
		"[日期时间]": now.Format("2006-01-02 15:04:05"),
	}

	defaultAutoTitle := "[套餐]"
	defaultAutoSubt := "[时长] 跳 [所有通用.用量] 免 [所有免流.用量]"
	defaultAutoDesc := "☸️通用总共 [通用有限.总] 🔯\n☯️通用已用 [通用有限.已用]🕎\n🕉通用剩余 [通用有限.剩余] ☪️\n♒️免流已用 [所有免流.已用] ⛎\n🕉今日通用 [所有通用.今日用量] 🕉\n🕉今日免流 [所有免流.今日用量] 🕉\n♈️联通时间 [联通时间]♌️"

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
		PackageName: pkgName,
		DurationStr: durationStr,
		DiffNormal:  diffNorm,
		DiffFree:    diffFree,
		TotalDiffMb: totalDiff,
		AutoTitle:   autoTitle,
		AutoContent: autoContent,
		BotContent:  botContent,
		AccKey:      accKey,
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

	// 🌟 后台可选回环检测协程（默认 0 由外部 Crontab 驱动；若设 >0 则由守护进程内部定时触发）
	loopMin, _ := strconv.Atoi(getEnv("AUTO_CHECK_INTERVAL_MIN", "0"))
	if loopMin > 0 {
		go func() {
			fmt.Printf("🔄 [Go-v4x] 启动内部回环巡检引擎 (每 %d 分钟巡检一次)\n", loopMin)
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
						"chat_id":    chatID,
						"text":       "👋 <b>[Go-v4x] 联通监控在线！</b>\n\n" +
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

	// 双独立阈值判定
	isNormTriggered := minNormUsage > 0 && res.DiffNormal >= minNormUsage
	isFreeTriggered := minFreeUsage > 0 && res.DiffFree >= minFreeUsage

	// 越级放行仅针对通用流量
	isBypass := alertBypassMb > 0 && res.DiffNormal >= alertBypassMb

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
				reason := fmt.Sprintf("通用跳点 +%s >= %s", formatFlow(res.DiffNormal), formatFlow(minNormUsage))
				if isBypass {
					reason += " [越级放行]"
				}
				triggerReasons = append(triggerReasons, reason)
			} else {
				fmt.Printf("⏳ [%s] 通用跳点已达标 (+%s)，但在冷却期内 (%s)，跳过该项推送\n",
					accTitle, formatFlow(res.DiffNormal), cooldownText(alertCooldown))
			}
		}

		// 2. 免流跳点判定（独立通道、独立冷却）
		if isFreeTriggered {
			if freeAlertCooldown <= 0 || acc.LastAlertFree == 0 || (now-acc.LastAlertFree) >= freeAlertCooldown.Milliseconds() {
				freePassed = true
				acc.LastAlertFree = now
				triggerReasons = append(triggerReasons, fmt.Sprintf("免流跳点 +%s >= %s", formatFlow(res.DiffFree), formatFlow(minFreeUsage)))
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
			triggerReasons = append(triggerReasons, fmt.Sprintf("通用跳点 +%s [抢锁超时强制放行]", formatFlow(res.DiffNormal)))
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

		finalAutoTitle := prefix + res.AutoTitle
		finalBotContent := strings.Replace(
			res.BotContent,
			"⚡ <b>联通实时跳点播报</b>",
			prefix+"<b>联通实时跳点播报</b>",
			1,
		)

		fmt.Printf("🚀 [%s] 触发报警 (%s)，发送通知！\n", accTitle, strings.Join(triggerReasons, " | "))
		sendDingTalk(finalAutoTitle, res.AutoContent)

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
	} else if !isNormTriggered && !isFreeTriggered {
		fmt.Printf("⏳ [%s] 本次通用(+%s / 阈值 %s)与免流(+%s / 阈值 %s)均未达标，静默不扰。\n",
			accTitle,
			formatFlow(res.DiffNormal), thresholdText(minNormUsage),
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
			cmd := exec.Command(execSelf, "--daemon")
			if err == nil {
				cmd.Stdout = logF
				cmd.Stderr = logF
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := cmd.Start(); err == nil {
				_ = cmd.Process.Release()
			}
			if logF != nil {
				_ = logF.Close()
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

	// 🌟 多账号支持：依次轮询每个 Cookie
	for idx, cookie := range cookies {
		accTitle := fmt.Sprintf("账号 %d", idx+1)
		fmt.Printf("\n========== 🚀 开始检测 [%s] ==========\n", accTitle)

		res, err := fetchAndCalculate(cookie, idx, true, 0)
		if err != nil {
			fmt.Printf("❌ [%s] 查询异常: %v\n", accTitle, err)

			var authErr *AuthError
			if errors.As(err, &authErr) {
				notifyFault(fmt.Sprintf("[%s] Cookie 已失效: %s", accTitle, authErr.Msg))
			} else {
				fmt.Printf("ℹ️ [%s] 为网络/网关临时波动 (非 Cookie 失效)，保持静默。\n", accTitle)
			}
			continue
		}

		fmt.Println("\n============== 📣 [v4x] 自动报警模版预览 📣 ==============")
		fmt.Printf("【%s】\n%s\n", res.AutoTitle, res.AutoContent)
		fmt.Println("==========================================================")
		fmt.Printf("⏱ 距上次检测: %s | 本次合计跳点: +%s (通用+%s, 免流+%s)\n",
			res.DurationStr, formatFlow(res.TotalDiffMb), formatFlow(res.DiffNormal), formatFlow(res.DiffFree))

		checkAndSendAlert(res, accTitle)
	}

	os.Exit(0)
}
