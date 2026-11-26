package config

// Field describes one editable setting.
type Field struct {
	Key     string `json:"key"`   // dot path, e.g. "scan.concurrency"
	Label   string `json:"label"` // shown in the panel
	Type    string `json:"type"`  // string | int | float | bool | list | text
	Help    string `json:"help,omitempty"`
	Restart bool   `json:"restart,omitempty"` // needs a process restart
	Secret  bool   `json:"secret,omitempty"`  // masked in the panel
}

// Group is a titled block of fields.
type Group struct {
	Title  string  `json:"title"`
	Fields []Field `json:"fields"`
}

// Schema lists everything the panel may edit. The token is deliberately absent.
func Schema() []Group {
	return []Group{
		{"运行", []Field{
			{Key: "listen", Label: "监听地址", Type: "string", Help: "如 :8080", Restart: true},
			{Key: "schedule", Label: "定时扫描", Type: "string", Help: "分 时 * * *，如 0 4 * * *"},
			{Key: "timezone", Label: "时区", Type: "string", Help: "如 Asia/Shanghai"},
			{Key: "data_dir", Label: "数据目录", Type: "string", Help: "容器内为 /data", Restart: true},
		}},
		{"扫描候选", []Field{
			{Key: "scan.subnets", Label: "WireGuard 网段", Type: "list", Help: "逗号分隔的 CIDR"},
			{Key: "scan.sample_per_subnet", Label: "每网段抽样", Type: "int", Help: "0 表示全量 256 个"},
			{Key: "scan.ports", Label: "端口", Type: "list", Help: "逗号分隔"},
			{Key: "scan.domain_targets", Label: "域名目标", Type: "list", Help: "如 engage.cloudflareclient.com:2408"},
			{Key: "scan.masque_hosts", Label: "MASQUE 入口", Type: "list", Help: "留空则不注册 MASQUE 设备"},
			{Key: "scan.masque_port", Label: "MASQUE 端口", Type: "int"},
			{Key: "scan.concurrency", Label: "探测并发", Type: "int"},
			{Key: "scan.rounds", Label: "每候选探测轮次", Type: "int"},
			{Key: "scan.timeout_ms", Label: "单次超时(ms)", Type: "int"},
		}},
		{"VLESS 节点", []Field{
			{Key: "vless.enabled", Label: "启用 VLESS", Type: "bool"},
			{Key: "vless.worker_host", Label: "Worker 域名", Type: "string", Help: "edgetunnel 的域名"},
			{Key: "vless.uuid", Label: "UUID", Type: "string", Secret: true},
			{Key: "vless.path", Label: "路径", Type: "string", Help: "默认 /"},
			{Key: "vless.port", Label: "端口", Type: "int"},
			{Key: "vless.fingerprint", Label: "TLS 指纹", Type: "string", Help: "chrome / firefox"},
			{Key: "vless.sources", Label: "公开优选源", Type: "list", Help: "每行一个 URL"},
			{Key: "vless.max_candidates", Label: "采集上限", Type: "int"},
			{Key: "vless.candidates", Label: "手填接入地址", Type: "list"},
			{Key: "vless.verify_domains", Label: "逐站验证", Type: "list", Help: "如 antigravity.google"},
			{Key: "vless.egress_probe", Label: "出口探测地址", Type: "string"},
			{Key: "vless.allowed_countries", Label: "允许出口国家", Type: "list", Help: "留空不过滤"},
			{Key: "vless.ech.enabled", Label: "启用 ECH", Type: "bool"},
			{Key: "vless.ech.public_name", Label: "ECH 公开名", Type: "string"},
			{Key: "vless.ech.doh", Label: "ECH DoH", Type: "string"},
			{Key: "vless.ech.clash_config", Label: "ECHConfigList", Type: "text", Help: "留空则自动获取"},
		}},
		{"门槛", []Field{
			{Key: "thresholds.max_latency_ms", Label: "延迟上限(ms)", Type: "float", Help: "存活判断"},
			{Key: "thresholds.masque_max_latency_ms", Label: "MASQUE 延迟上限(ms)", Type: "float"},
			{Key: "thresholds.max_jitter_ms", Label: "抖动上限(ms)", Type: "float"},
			{Key: "thresholds.max_loss_pct", Label: "丢包上限(%)", Type: "float"},
			{Key: "thresholds.min_speed_mbps", Label: "速率下限(Mbps)", Type: "float"},
			{Key: "thresholds.speed_ref_mbps", Label: "速率满分基准(Mbps)", Type: "float"},
			{Key: "thresholds.min_stability", Label: "稳定性下限", Type: "float", Help: "0-100，0 表示不设限"},
		}},
		{"入选数量", []Field{
			{Key: "top.wg", Label: "WireGuard", Type: "int"},
			{Key: "top.wg_domain", Label: "WireGuard 域名", Type: "int"},
			{Key: "top.masque", Label: "MASQUE", Type: "int"},
			{Key: "top.vless", Label: "VLESS", Type: "int"},
			{Key: "stability.min_hits", Label: "稳定性窗口", Type: "int", Help: "1 = 关闭"},
			{Key: "stability.bootstrap", Label: "历史不足时放行", Type: "bool"},
		}},
		{"测速", []Field{
			{Key: "speed_test.enabled", Label: "启用测速", Type: "bool"},
			{Key: "speed_test.url", Label: "测速目标", Type: "string", Help: "必须是非 Cloudflare 地址"},
			{Key: "speed_test.shortlist", Label: "短名单节点数", Type: "int"},
			{Key: "speed_test.duration_s", Label: "单节点时长(s)", Type: "int"},
			{Key: "speed_test.max_bytes_mb", Label: "单节点流量上限(MB)", Type: "int", Help: "0 表示不限"},
			{Key: "speed_test.idle_enabled", Label: "空闲存活测试", Type: "bool"},
			{Key: "speed_test.idle_seconds", Label: "空闲时长(s)", Type: "int"},
			{Key: "speed_test.required", Label: "测不出速率即淘汰", Type: "bool"},
			{Key: "speed_test.cooldown_ms", Label: "测速前冷却(ms)", Type: "int"},
		}},
		{"订阅", []Field{
			{Key: "subscription.name", Label: "订阅名称", Type: "string"},
			{Key: "subscription.update_hours", Label: "客户端更新间隔(h)", Type: "int"},
			{Key: "subscription.include_masque", Label: "包含 MASQUE", Type: "bool"},
			{Key: "subscription.test_url", Label: "延迟测试地址", Type: "string"},
		}},
	}
}
