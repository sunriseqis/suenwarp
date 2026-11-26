package config

import (
	"os"
	"strconv"
	"strings"
)

// ApplyEnv overlays environment variables onto a loaded config.
//
// Everything the container typically needs to vary per deployment can be set
// without editing config.yaml, which is what the compose .env file feeds.
//
//	WARPSUB_LISTEN, WARPSUB_TOKEN, WARPSUB_DATA_DIR, WARPSUB_SCHEDULE, WARPSUB_TZ, WARPSUB_LOG_LEVEL
//	WARPSUB_VLESS_HOST, WARPSUB_VLESS_UUID, WARPSUB_VLESS_PATH
//	WARPSUB_VLESS_ENABLED, WARPSUB_VLESS_SOURCES, WARPSUB_VLESS_VERIFY_DOMAINS
//	WARPSUB_ALLOWED_COUNTRIES, WARPSUB_EGRESS_PROBE
//	WARPSUB_SPEED_URL, WARPSUB_SPEED_ENABLED, WARPSUB_SHORTLIST
//	WARPSUB_SCAN_CONCURRENCY
func (c *Config) ApplyEnv() {
	setStr(&c.Listen, "WARPSUB_LISTEN")
	setStr(&c.Token, "WARPSUB_TOKEN")
	setStr(&c.Schedule, "WARPSUB_SCHEDULE")
	setStr(&c.Timezone, "WARPSUB_TZ")
	setStr(&c.LogLevel, "WARPSUB_LOG_LEVEL")
	setStr(&c.DataDir, "WARPSUB_DATA_DIR")

	if v, ok := os.LookupEnv("WARPSUB_VLESS_ENABLED"); ok {
		c.VLESS.Enabled = truthy(v)
	}
	setStr(&c.VLESS.WorkerHost, "WARPSUB_VLESS_HOST")
	setStr(&c.VLESS.UUID, "WARPSUB_VLESS_UUID")
	setStr(&c.VLESS.Path, "WARPSUB_VLESS_PATH")
	if v, ok := os.LookupEnv("WARPSUB_VLESS_SOURCES"); ok {
		c.VLESS.Sources = splitList(v)
	}
	if v, ok := os.LookupEnv("WARPSUB_VLESS_VERIFY_DOMAINS"); ok {
		c.VLESS.VerifyDomains = splitList(v)
	}
	if v, ok := os.LookupEnv("WARPSUB_ALLOWED_COUNTRIES"); ok {
		c.VLESS.AllowedCountries = splitList(v)
	}
	setStr(&c.VLESS.EgressProbe, "WARPSUB_EGRESS_PROBE")

	if v, ok := os.LookupEnv("WARPSUB_SPEED_ENABLED"); ok {
		c.Speed.Enabled = truthy(v)
	}
	setStr(&c.Speed.URL, "WARPSUB_SPEED_URL")
	if v, ok := os.LookupEnv("WARPSUB_SHORTLIST"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			c.Speed.Shortlist = n
		}
	}
	if v, ok := os.LookupEnv("WARPSUB_SCAN_CONCURRENCY"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			c.Scan.Concurrency = n
		}
	}
}

func setStr(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		*dst = strings.TrimSpace(v)
	}
}

func splitList(v string) []string {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == ';' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
