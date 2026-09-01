package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// renderTemplate 必须单遍替换：占位符替换进来的值不能再被二次匹配。
func TestRenderTemplateNoReSubstitution(t *testing.T) {
	vars := map[string]string{
		"[套餐名]": "含[用量]字样的套餐",
		"[用量]":  "123M",
	}
	got := renderTemplate("套餐=[套餐名] 用量=[用量]", vars)
	want := "套餐=含[用量]字样的套餐 用量=123M"
	if got != want {
		t.Fatalf("单遍替换失败\n got: %q\nwant: %q", got, want)
	}
}

// 长键优先：短键不得截胡长键。
func TestRenderTemplateLongestKeyWins(t *testing.T) {
	vars := map[string]string{
		"[所有通用.用]":  "SHORT",
		"[所有通用.用量]": "LONG",
	}
	if got := renderTemplate("[所有通用.用量]", vars); got != "LONG" {
		t.Fatalf("长键未优先: %q", got)
	}
}

func TestRenderTemplateEscapedNewline(t *testing.T) {
	if got := renderTemplate(`a\nb`, nil); got != "a\nb" {
		t.Fatalf("\\n 未转义: %q", got)
	}
}

func TestParseRefreshCallback(t *testing.T) {
	orig := botDiffMinutes
	defer func() { botDiffMinutes = orig }()
	botDiffMinutes = 30
	cases := []struct {
		in      string
		min     int
		idx     int
		matched bool
	}{
		{"refresh_0_0", 0, 0, true},   // ⚡ 实时跳点 = 巡检
		{"refresh_0_2", 0, 2, true},   // 旧版 ⚡ 同为巡检语义
		{"refresh_30_2", 30, 2, true}, // 🔍 30分钟跳点
		{"refresh_-1_1", -1, 1, true}, // 总余量
		{"refresh_-2_0", 0, 0, true},  // 8b207d7 过渡版巡检回放 → 巡检
		{"refresh_-2_3", 0, 3, true},
		{"refresh_0", 0, 0, true},    // 旧格式兼容：巡检语义
		{"refresh_-1", -1, 0, true},  // 旧格式兼容
		{"refresh_jump", 0, 0, true}, // 最早期版本：巡检语义
		{"refresh_60", 60, 0, true},
		{"refresh_abc", 0, 0, false},
		{"other", 0, 0, false},
		{"refresh_30_-5", 30, 0, true}, // 负下标回落 0
	}
	for _, c := range cases {
		min, idx, ok := parseRefreshCallback(c.in)
		if ok != c.matched || (ok && (min != c.min || idx != c.idx)) {
			t.Errorf("%s => (%d,%d,%v)，期望 (%d,%d,%v)", c.in, min, idx, ok, c.min, c.idx, c.matched)
		}
	}
}

// 统一静态键盘：所有卡片都是 [⚡ 实时跳点][🔍 N分钟跳点] / [📦 套餐总余量]。
// ⚡ 编码 refresh_0（巡检），🔍 编码 refresh_<botDiffMinutes>，解析后各归其位。
func TestInlineKeyboardStaticLayout(t *testing.T) {
	orig := botDiffMinutes
	defer func() { botDiffMinutes = orig }()
	botDiffMinutes = 30

	kb := buildTGInlineKeyboard(1)
	rows := kb["inline_keyboard"].([][]map[string]string)
	if len(rows) != 2 || len(rows[0]) != 2 || len(rows[1]) != 1 {
		t.Fatalf("期望两行 [2键][1键]，实际 %v", rows)
	}
	want := []struct{ text, data string }{
		{"⚡ 实时跳点", "refresh_0_1"},
		{"🔍 30分钟跳点", "refresh_30_1"},
		{"📦 套餐总余量", "refresh_-1_1"},
	}
	got := []map[string]string{}
	for _, row := range rows {
		got = append(got, row...)
	}
	for i, w := range want {
		if got[i]["text"] != w.text || got[i]["callback_data"] != w.data {
			t.Errorf("第 %d 键 = %v，期望 %s/%s", i+1, got[i], w.text, w.data)
		}
	}
	// 键与回调语义往返一致
	for _, w := range want {
		min, _, ok := parseRefreshCallback(w.data)
		if !ok {
			t.Fatalf("%s 解析失败", w.data)
		}
		wantMin := map[string]int{"refresh_0_1": 0, "refresh_30_1": 30, "refresh_-1_1": -1}[w.data]
		if min != wantMin {
			t.Errorf("%s 解析 => %d，期望 %d", w.data, min, wantMin)
		}
	}
}

// 🔍 键的分钟数与 callback_data 必须跟随 botDiffMinutes，否则按钮与指令行为分叉。
func TestInlineKeyboardJumpKeyFollowsBotMinutes(t *testing.T) {
	orig := botDiffMinutes
	defer func() { botDiffMinutes = orig }()

	botDiffMinutes = 45
	kb := buildTGInlineKeyboard(1)
	rows := kb["inline_keyboard"].([][]map[string]string)
	if rows[0][1]["text"] != "🔍 45分钟跳点" || rows[0][1]["callback_data"] != "refresh_45_1" {
		t.Fatalf("🔍 键 = %v，期望 🔍 45分钟跳点/refresh_45_1", rows[0][1])
	}
	// ⚡ 键不随 botDiffMinutes 变化：永远是巡检
	if rows[0][0]["text"] != "⚡ 实时跳点" || rows[0][0]["callback_data"] != "refresh_0_1" {
		t.Fatalf("⚡ 键 = %v，期望 ⚡ 实时跳点/refresh_0_1", rows[0][0])
	}
}

// 「🔍 30分钟跳点」样式的文本（底部快捷键盘第二键）跟随标签里的数字。
func TestJumpLabelTextParsing(t *testing.T) {
	cases := []struct {
		in    string
		min   int
		match bool
	}{
		{"🔍 30分钟跳点", 30, true},
		{"🔍 60分钟跳点", 60, true},
		{"🔍  30 分钟跳点", 30, true},
		{"⚡ 实时跳点", 0, false},
		{"30分钟", 0, false}, // 由纯数字分支处理，不该撞到这里
		{"🔍 分钟跳点", 0, false},
	}
	for _, c := range cases {
		m := jumpLabelRe.FindStringSubmatch(c.in)
		if (m != nil) != c.match {
			t.Errorf("%q 匹配 => %v，期望 %v", c.in, m != nil, c.match)
			continue
		}
		if m != nil {
			if n, err := strconv.Atoi(m[1]); err != nil || n != c.min {
				t.Errorf("%q 解析出 %d，期望 %d", c.in, n, c.min)
			}
		}
	}
}

// 指纹按行计算：改一行不应影响另一行的指纹。
func TestEnvCredFingerprintPerLine(t *testing.T) {
	a1 := envCredFingerprint("cookieA", "tokA")
	a2 := envCredFingerprint("cookieA", "tokA")
	b := envCredFingerprint("cookieB", "tokA")
	if a1 != a2 {
		t.Fatal("同输入指纹不稳定")
	}
	if a1 == b {
		t.Fatal("不同 cookie 行指纹相同")
	}
	if envCredFingerprint(" cookieA ", "tokA") != a1 {
		t.Fatal("未忽略首尾空白")
	}
}

func TestMobileFromCookie(t *testing.T) {
	if got := mobileFromCookie("x=1&c_mobile=13800138000&y=2"); got != "13800138000" {
		t.Fatalf("c_mobile 解析失败: %q", got)
	}
	if got := mobileFromCookie("u_account=13900139000;"); got != "13900139000" {
		t.Fatalf("u_account 解析失败: %q", got)
	}
	if got := mobileFromCookie("nothing=here"); got != "" {
		t.Fatalf("无手机号时应返回空: %q", got)
	}
}

// 手机号相同、Cookie 全文不同 → key 必须稳定（换 Cookie 不丢基线）。
func TestAccountKeyStableAcrossCookieRotation(t *testing.T) {
	k1 := accountKey("sess=aaa&c_mobile=13800138000")
	k2 := accountKey("sess=bbb&c_mobile=13800138000")
	if k1 != k2 {
		t.Fatalf("换 Cookie 后 key 漂移: %s vs %s", k1, k2)
	}
	if k1 == accountKey("sess=aaa&c_mobile=13800138001") {
		t.Fatal("不同手机号 key 相同")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.json")
	if err := writeFileAtomic(p, []byte("hello"), 0600); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "hello" {
		t.Fatalf("内容不符: %q", b)
	}
	if err := writeFileAtomic(p, []byte("world!!"), 0600); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "world!!" {
		t.Fatalf("覆盖后内容不符: %q", b)
	}
	// 不得留下临时文件
	if m, _ := filepath.Glob(p + ".*.tmp"); len(m) != 0 {
		t.Fatalf("残留临时文件: %v", m)
	}
}

func TestSplitCookieLinesDropsShortLines(t *testing.T) {
	in := "short\n" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" + "  \n" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbb\r"
	got := splitCookieLines(in)
	if len(got) != 2 {
		t.Fatalf("期望 2 行有效，得到 %d: %v", len(got), got)
	}
}

// 旧 key 迁移必须挑历史最丰富的那份，而不是第一个命中的。
func TestPickLegacyAccountPrefersRichest(t *testing.T) {
	cookie := "sess=aaa&c_mobile=13800138000"
	store := &StoreData{Accounts: map[string]*AccountStore{
		legacyCookieKey(cookie): {History: make([]SnapshotRecord, 3)},
		"acc_0":                 {History: make([]SnapshotRecord, 100)},
	}}
	key, acc := pickLegacyAccount(store, cookie, 0, accountKey(cookie))
	if key != "acc_0" || acc == nil || len(acc.History) != 100 {
		t.Fatalf("未选中历史最丰富的条目: key=%s", key)
	}
}
