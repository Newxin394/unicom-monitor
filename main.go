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
	"sort"
	"strconv"
	"strings"
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

type AccountStore struct {
	Last      *UsageSnapshot `json:"last,omitempty"`
	LastTime  int64          `json:"lastTime,omitempty"`
	Today     *UsageSnapshot `json:"today,omitempty"`
	TodayDate int64          `json:"todayDate,omitempty"`

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
		minFreeUsage = 2000
	}

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

var configShCache map[string]string

func loadConfigSh() {
	if configShCache != nil {
		return
	}
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
		if json.Unmarshal(raw, store) == nil && store.Accounts != nil {
			return store
		}
	}

	storeMainHealthy.Store(false)
	fmt.Println("⚠️ [存储] 主数据损坏，尝试用 .bak 恢复...")

	if bakRaw, err := os.ReadFile(bakFile); err == nil {
		if json.Unmarshal(bakRaw, store) == nil && store.Accounts != nil {
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
		return nil
	}

	var list []string
	for _, l := range strings.Split(cookieStr, "\n") {
		trimmed := strings.TrimSpace(strings.Trim(l, "\r`"))
		if len(trimmed) > 20 {
			list = append(list, trimmed)
		}
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

func fetchAndCalculate(cookie string, accountIndex int, updateBaseline bool) (*QueryResult, error) {
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
				isFree := item.FlowType == "2" || item.FlowType == "3" ||
					res.Type == "MlFlowdetailsList" ||
					strings.Contains(name, "免流") || strings.Contains(name, "定向")

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
				voiceTotal += toFloat(item.Total)
				voiceUsed += toFloat(item.Use)
				voiceRemain += toFloat(item.Remain)
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

		var dirty bool

		// 今日基线处理
		if acc.Today == nil || acc.TodayDate != todayZero || normUsed < acc.Today.NormalUsed {
			if updateBaseline || acc.Today == nil || acc.TodayDate != todayZero {
				acc.Today = currentSnap
				acc.TodayDate = todayZero
				dirty = true
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
			durationStr = formatDuration(now.Sub(time.UnixMilli(acc.LastTime)))

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

		if updateBaseline {
			acc.Last = currentSnap
			acc.LastTime = now.UnixMilli()
			dirty = true
		}
		return dirty
	})

	if lockErr != nil {
		fmt.Printf("⚠️ [存储] 本次基线读写失败 (%v)，跳点数据不可信\n", lockErr)
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

	defaultBotTitle := "⚡ <b>联通实时跳点播报</b>"
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

func runTGDaemon() {
	if tgBotToken == "" {
		return
	}

	if !claimPidFile() {
		fmt.Println("ℹ️ [Go-v4x] 已有守护进程在运行，本次不重复启动")
		return
	}

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

	store := loadStoreSafe()
	offset := store.TGOffset

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
				store.TGOffset = offset
			}
			r.Body.Close()
		}
	}

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
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
				CallbackQuery *struct {
					ID      string `json:"id"`
					Data    string `json:"data"`
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

				if chatID != owner {
					continue
				}

				if text == "/start" || text == "/help" {
					tgSend("sendMessage", map[string]interface{}{
						"chat_id":    chatID,
						"text":       "👋 [Go-v4x] 监控在线！\n点击下方大按钮随时查：",
						"parse_mode": "HTML",
						"reply_markup": map[string]interface{}{
							"keyboard": [][]map[string]string{
								{{"text": "⚡ 实时查跳点"}, {"text": "📦 套餐总余量"}},
							},
							"resize_keyboard": true,
						},
					})
				} else if text == "/check" || text == "⚡ 实时查跳点" || text == "📦 套餐总余量" {
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

						go func(c string, cid string) {
							defer atomic.StoreInt32(&isQueryingAtomic, 0)
							res, err := fetchAndCalculate(c, 0, false)
							if err != nil {
								tgSend("sendMessage", map[string]interface{}{
									"chat_id": cid,
									"text":    fmt.Sprintf("❌ 查询失败: %s", html.EscapeString(err.Error())),
								})
							} else {
								tgSend("sendMessage", map[string]interface{}{
									"chat_id":    cid,
									"text":       res.BotContent,
									"parse_mode": "HTML",
									"reply_markup": map[string]interface{}{
										"inline_keyboard": [][]map[string]string{
											{{"text": "🔄 刷新跳点", "callback_data": "refresh_jump"}},
										},
									},
								})
							}
						}(cookies[0], chatID)
					}
				}
			}

			if upd.CallbackQuery != nil {
				cq := upd.CallbackQuery
				chatID := strconv.FormatInt(cq.Message.Chat.ID, 10)
				curStore := loadStoreSafe()
				owner := tgUserID
				if owner == "" {
					owner = curStore.OwnerID
				}

				if chatID == owner && cq.Data == "refresh_jump" {
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

					tgSend("answerCallbackQuery", map[string]interface{}{
						"callback_query_id": cq.ID,
						"text":              "正在查询最新跳点...",
					})

					cookies := getCookies()
					if len(cookies) > 0 {
						go func(c string, cid string, msgID int64) {
							defer atomic.StoreInt32(&isQueryingAtomic, 0)
							res, err := fetchAndCalculate(c, 0, false)
							if err == nil {
								tgSend("editMessageText", map[string]interface{}{
									"chat_id":    cid,
									"message_id": msgID,
									"text":       res.BotContent,
									"parse_mode": "HTML",
									"reply_markup": map[string]interface{}{
										"inline_keyboard": [][]map[string]string{
											{{"text": "🔄 刷新跳点", "callback_data": "refresh_jump"}},
										},
									},
								})
							}
						}(cookies[0], chatID, cq.Message.MessageID)
					} else {
						atomic.StoreInt32(&isQueryingAtomic, 0)
					}
				}
			}
		}

		if offset != store.TGOffset {
			_, _ = lockAndModifyStore(func(s *StoreData) bool {
				s.TGOffset = offset
				return true
			})
			store.TGOffset = offset
		}

		time.Sleep(500 * time.Millisecond)
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

		res, err := fetchAndCalculate(cookie, idx, true)
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

		// 双独立阈值判定
		isNormTriggered := minNormUsage > 0 && res.DiffNormal >= minNormUsage
		isFreeTriggered := minFreeUsage > 0 && res.DiffFree >= minFreeUsage

		// 越级放行仅针对通用流量
		isBypass := alertBypassMb > 0 && res.DiffNormal >= alertBypassMb

		var allowSend bool
		var normPassed, freePassed bool
		var triggerReasons []string
		now := time.Now().In(cst).UnixMilli()

		_, _ = lockAndModifyStore(func(s *StoreData) bool {
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

		if allowSend {
			// 🌟 动态注入前缀：
			// 🔴 [跳点]（只有通用跳点达标）
			// 🟢 [免流]（只有免流跳点达标）
			// 🟡 [混合]（通用与免流同时达标）
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
					"chat_id":    owner,
					"text":       finalBotContent,
					"parse_mode": "HTML",
					"reply_markup": map[string]interface{}{
						"inline_keyboard": [][]map[string]string{
							{{"text": "🔄 刷新跳点", "callback_data": "refresh_jump"}},
						},
					},
				})
			}
		} else if !isNormTriggered && !isFreeTriggered {
			fmt.Printf("⏳ [%s] 本次通用(+%s / 阈值 %s)与免流(+%s / 阈值 %s)均未达标，静默不扰。\n",
				accTitle,
				formatFlow(res.DiffNormal), thresholdText(minNormUsage),
				formatFlow(res.DiffFree), thresholdText(minFreeUsage))
		}
	}

	os.Exit(0)
}
