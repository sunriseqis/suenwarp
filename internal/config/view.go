package config

import (
	"os"
	"sort"
	"strings"
)

// EnvKeys lists every environment variable this build understands.
var EnvKeys = []string{
	"WARPSUB_LISTEN", "WARPSUB_TOKEN", "WARPSUB_SCHEDULE", "WARPSUB_TZ",
	"WARPSUB_LOG_LEVEL", "WARPSUB_DATA_DIR",
	"WARPSUB_VLESS_ENABLED", "WARPSUB_VLESS_HOST", "WARPSUB_VLESS_UUID",
	"WARPSUB_VLESS_PATH", "WARPSUB_VLESS_SOURCES", "WARPSUB_VLESS_VERIFY_DOMAINS",
	"WARPSUB_ALLOWED_COUNTRIES", "WARPSUB_EGRESS_PROBE",
	"WARPSUB_SPEED_ENABLED", "WARPSUB_SPEED_URL", "WARPSUB_SHORTLIST",
	"WARPSUB_SCAN_CONCURRENCY",
}

// ActiveEnv returns the env vars that are actually set, with secrets masked.
// The panel uses it to show which values came from the environment instead of
// the file, which is otherwise invisible.
func ActiveEnv() map[string]string {
	out := map[string]string{}
	for _, k := range EnvKeys {
		v, ok := os.LookupEnv(k)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if strings.Contains(k, "TOKEN") || strings.Contains(k, "UUID") {
			out[k] = mask(v)
			continue
		}
		out[k] = v
	}
	return out
}

// Redacted returns a copy safe for the panel: secrets replaced by a fixed mask.
func (c Config) Redacted() Config {
	if c.Token != "" {
		c.Token = mask(c.Token)
	}
	if c.VLESS.UUID != "" {
		c.VLESS.UUID = mask(c.VLESS.UUID)
	}
	if c.VLESS.ECH.ClashConfig != "" {
		c.VLESS.ECH.ClashConfig = mask(c.VLESS.ECH.ClashConfig)
	}
	return c
}

func mask(s string) string {
	if len(s) <= 6 {
		return "**"
	}
	return s[:3] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// Describe renders the tunables that matter to a user, in a stable order, so
// the panel can show them without duplicating the struct layout in JavaScript.
func (c Config) Describe() []Section {
	return []Section{
		{Title: "扫描候选", Rows: [][2]string{
			{"网段", strings.Join(c.Scan.Subnets, ", ")},
			{"每网段抽样", itoa(c.Scan.SamplePerSubnet) + "（0 = 全量 256）"},
			{"端口", joinInts(c.Scan.Ports)},
			{"域名目标", strings.Join(c.Scan.DomainTargets, ", ")},
			{"MASQUE 入口", strings.Join(c.Scan.MasqueHosts, ", ")},
			{"并发 / 轮次 / 超时", itoa(c.Scan.Concurrency) + " / " + itoa(c.Scan.Rounds) + " / " + itoa(c.Scan.TimeoutMS) + "ms"},
		}},
		{Title: "VLESS 与站点", Rows: [][2]string{
			{"开关", boolStr(c.VLESS.Enabled)},
			{"Worker 域名", c.VLESS.WorkerHost},
			{"路径", c.VLESS.Path},
			{"公开源", strings.Join(c.VLESS.Sources, ", ")},
			{"手填地址", strings.Join(c.VLESS.Candidates, ", ")},
			{"采集上限", itoa(c.VLESS.MaxCandidates)},
			{"逐站验证", strings.Join(c.VLESS.VerifyDomains, ", ")},
			{"出口探测", c.VLESS.EgressProbe},
			{"允许出口国家", strings.Join(c.VLESS.AllowedCountries, ", ")},
			{"ECH", boolStr(c.VLESS.ECH.Enabled) + " " + c.VLESS.ECH.PublicName},
		}},
		{Title: "门槛与排序", Rows: [][2]string{
			{"延迟上限", ftoa(c.Thresh.MaxLatencyMS) + "ms（MASQUE " + ftoa(c.Thresh.MasqueMaxLatencyMS) + "ms）"},
			{"抖动 / 丢包上限", ftoa(c.Thresh.MaxJitterMS) + "ms / " + ftoa(c.Thresh.MaxLossPct) + "%"},
			{"速率下限 / 满分基准", ftoa(c.Thresh.MinSpeedMbps) + " / " + ftoa(c.Thresh.SpeedRefMbps) + " Mbps"},
			{"稳定性下限", ftoa(c.Thresh.MinStability)},
			{"Top N", "wg " + itoa(c.Top.WG) + " · wgd " + itoa(c.Top.WGDomain) + " · mq " + itoa(c.Top.Masque) + " · vl " + itoa(c.Top.Vless)},
			{"稳定性窗口", itoa(c.Stable.MinHits) + " 次（bootstrap " + boolStr(c.Stable.Bootstrap) + "）"},
		}},
		{Title: "测速", Rows: [][2]string{
			{"启用", boolStr(c.Speed.Enabled)},
			{"目标", c.Speed.URL},
			{"时长 / 流量上限", itoa(c.Speed.DurationS) + "s / " + itoa(c.Speed.MaxBytesMB) + "MB"},
			{"短名单", itoa(c.Speed.Shortlist)},
			{"空闲存活", boolStr(c.Speed.IdleEnabled) + " " + itoa(c.Speed.IdleSeconds) + "s"},
		}},
		{Title: "运行", Rows: [][2]string{
			{"监听", c.Listen},
			{"定时", c.Schedule + " (" + c.Timezone + ")"},
			{"数据目录", c.DataDir},
			{"订阅名 / 更新间隔", c.Subtpl.Name + " / " + itoa(c.Subtpl.UpdateHours) + "h"},
			{"回写 edg", boolStr(c.Writeback.Enabled) + " " + c.Writeback.BaseURL},
			{"v2rayA 推送", boolStr(c.V2raya.Enabled) + " " + c.V2raya.BaseURL},
		}},
	}
}

// Section is one block of key/value rows for the panel.
type Section struct {
	Title string      `json:"title"`
	Rows  [][2]string `json:"rows"`
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func ftoa(v float64) string {
	if v == float64(int64(v)) {
		return itoa(int(v))
	}
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(ftoaRaw(v), ".", ".", 1), "0"), ".")
}

func ftoaRaw(v float64) string {
	// two decimal places is enough for every threshold we expose
	neg := v < 0
	if neg {
		v = -v
	}
	i := int64(v)
	f := int64((v-float64(i))*100 + 0.5)
	s := itoa(int(i)) + "."
	if f < 10 {
		s += "0"
	}
	s += itoa(int(f))
	if neg {
		return "-" + s
	}
	return s
}

func joinInts(v []int) string {
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, itoa(n))
	}
	sort.SliceStable(parts, func(i, j int) bool { return false })
	return strings.Join(parts, ", ")
}

func boolStr(b bool) string {
	if b {
		return "开"
	}
	return "关"
}
