// Command warp-sub measures Cloudflare WARP and VLESS endpoints and serves
// subscriptions for v2rayA and Clash/mihomo.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"warpsub/internal/account"
	"warpsub/internal/config"
	"warpsub/internal/ech"
	"warpsub/internal/httpapi"
	"warpsub/internal/model"
	"warpsub/internal/scan"
	"warpsub/internal/stability"
	"warpsub/internal/store"
	"warpsub/internal/v2raya"
	"warpsub/internal/writeback"
)

const version = "0.1.0"

// logFilter drops the stream-close chatter connect-ip-go emits when a
// CONNECT-IP attempt is torn down; it is expected noise, not a real error.
type logFilter struct{ dst io.Writer }

func (f logFilter) Write(p []byte) (int, error) {
	msg := string(p)
	for _, noisy := range []string{"handling stream failed", "writing to stream failed"} {
		if strings.Contains(msg, noisy) {
			return len(p), nil
		}
	}
	return f.dst.Write(p)
}

// mergeMap sets one key of an overlay map into the base map.
func mergeMap(base map[string]any, key string, v any) {
	config.SetPath(base, key, v)
}

func main() {
	log.SetOutput(logFilter{dst: os.Stderr})
	var (
		cfgPath = flag.String("config", "config.yaml", "path to config.yaml")
		scanOne = flag.Bool("scan", false, "run one scan and exit")
		showVer = flag.Bool("version", false, "print version")
		fullScan = flag.Bool("full", false, "scan every address of every subnet (slow)")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("warp-sub", version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	// panel edits live in data/override.json and win over config.yaml
	if ov, err := config.LoadOverlay(cfg.DataDir); err == nil && ov != nil {
		base := cfg.Map()
		for k, v := range ov {
			mergeMap(base, k, v)
		}
		if merged, err := config.FromMap(base); err == nil {
			cfg = merged
			log.Printf("applied panel overrides from %s", config.OverlayPath(cfg.DataDir))
		}
	}
	cfg.ApplyEnv()
	holder := config.NewHolder(cfg)
	if cfg.Schedule == "" {
		cfg.Schedule = "0 4 * * *"
	}

	st := store.New(cfg.DataDir)
	if err := st.Load(); err != nil {
		log.Printf("warn: load report: %v", err)
	}
	if _, err := st.LoadHistory(); err != nil {
		log.Printf("warn: load history: %v", err)
	}

	acctStore := account.NewStore(cfg.DataDir)
	acct, err := acctStore.Load()
	if err != nil {
		log.Printf("warn: load account: %v", err)
	}
	if acct == nil {
		if !cfg.Warp.AutoRegister {
			log.Fatalf("no WARP account in %s/account.json and auto_register is off", cfg.DataDir)
		}
		log.Printf("registering a new WARP device ...")
		acct, err = account.Register()
		if err != nil {
			log.Fatalf("register: %v", err)
		}
		if err := acctStore.Save(acct); err != nil {
			log.Fatalf("save account: %v", err)
		}
		log.Printf("account ready: id=%s client_id=%s v4=%s", acct.ID, acct.ClientID, acct.AddressV4)
	} else {
		log.Printf("account loaded: client_id=%s v4=%s", acct.ClientID, acct.AddressV4)
	}
	if cfg.Warp.LicenseKey != "" && acct.License != cfg.Warp.LicenseKey {
		if err := acct.ApplyLicense(cfg.Warp.LicenseKey); err != nil {
			log.Printf("warn: apply license: %v", err)
		} else {
			acctStore.Save(acct)
			log.Printf("license applied")
		}
	}

	masqueStore := account.NewMasqueStore(cfg.DataDir)
	masqueAcct, err := masqueStore.Load()
	if err != nil {
		log.Printf("warn: load masque account: %v", err)
	}
	wantMasque := cfg.Subtpl.IncludeMasque && len(cfg.Scan.MasqueHosts) > 0
	if masqueAcct == nil && wantMasque {
		log.Printf("registering a MASQUE (ECDSA) device ...")
		masqueAcct, err = account.RegisterMasque()
		if err != nil {
			log.Printf("warn: masque register failed (MASQUE nodes will be skipped): %v", err)
			masqueAcct = nil
		} else if err := masqueStore.Save(masqueAcct); err != nil {
			log.Printf("warn: save masque account: %v", err)
		} else {
			log.Printf("masque device ready: id=%s v4=%s", masqueAcct.ID, masqueAcct.AddressV4)
		}
	}

	// ECH: mihomo needs the concrete ECHConfigList, so resolve it via DoH when
	// the user did not paste one by hand.
	if cfg.VLESS.Enabled && cfg.VLESS.ECH.Enabled && cfg.VLESS.ECH.ClashConfig == "" {
		host := cfg.VLESS.WorkerHost
		if host != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			list, err := ech.FetchConfigList(ctx, cfg.VLESS.ECH.DoH, host)
			cancel()
			if err != nil {
				log.Printf("vless.ech: 无法自动获取 ECHConfigList（clash 侧将不带 ECH）: %v", err)
			} else {
				cfg.VLESS.ECH.ClashConfig = list
				log.Printf("vless.ech: 已获取 ECHConfigList（%d 字节），clash 侧将启用 ECH", len(list))
			}
		}
	}

	wb := writeback.New(cfg.DataDir)
	if cfg.Writeback.BaseURL != "" || cfg.Writeback.Password != "" {
		cur := wb.Settings()
		if cur.BaseURL == "" && cur.Password == "" {
			_ = wb.Update(writeback.Settings{
				Enabled:  cfg.Writeback.Enabled,
				BaseURL:  cfg.Writeback.BaseURL,
				Password: cfg.Writeback.Password,
				Auto:     cfg.Writeback.Auto,
			})
			log.Printf("writeback initialised from config: %s (enabled=%v auto=%v)",
				cfg.Writeback.BaseURL, cfg.Writeback.Enabled, cfg.Writeback.Auto)
		}
	}

	v2a := v2raya.New(cfg.DataDir)
	if cfg.V2raya.BaseURL != "" {
		cur := v2a.Settings()
		if cur.BaseURL == "" {
			_ = v2a.Update(v2raya.Settings{
				Enabled:  cfg.V2raya.Enabled,
				BaseURL:  cfg.V2raya.BaseURL,
				Username: cfg.V2raya.Username,
				Password: cfg.V2raya.Password,
				Auto:     cfg.V2raya.Auto,
				SubURL:   cfg.V2raya.SubURL,
			})
			log.Printf("v2raya initialised from config: %s", cfg.V2raya.BaseURL)
		}
	}

	stab := stability.New(cfg.DataDir)

	buildScanner := func(c config.Config) *scan.Scanner {
		sc := scan.New(c, acct, masqueAcct, st)
		sc.SetWriteback(wb)
		sc.SetV2raya(v2a)
		sc.SetStability(stab)
		return sc
	}

	runScan := func(ctx context.Context, opts scan.Options) (model.Report, error) {
		st.SetRunning(true, time.Now().Format("2006-01-02 15:04:05"))
		defer st.SetRunning(false, "")
		// rebuilt every run so panel edits apply without a restart
		return buildScanner(holder.Get()).Run(ctx, opts)
	}

	if *scanOne {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		rep, err := runScan(ctx, scan.Options{Full: *fullScan})
		if err != nil {
			log.Fatalf("scan: %v", err)
		}
		fmt.Printf("scan finished: %d candidates, %d passed, %.0fs\n", rep.Candidates, rep.Passed, rep.DurationSec)
		for _, n := range rep.Nodes {
			fmt.Printf("  [%s] %s %s:%d  %.1fms  %.1f/100\n", n.Class, n.Server, n.Server, n.Port, n.LatencyMS, n.Score)
		}
		return
	}

	srv := httpapi.New(holder, acct, masqueAcct, st, acctStore, wb, v2a, runScan)

	go scheduleLoop(holder, runScan)

	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler()}
	go func() {
		log.Printf("listening on %s", cfg.Listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
}

// scheduleLoop runs a daily scan at the configured cron time.
func scheduleLoop(holder *config.Holder, run func(context.Context, scan.Options) (model.Report, error)) {
	cfg := holder.Get()
	spec, err := parseDaily(cfg.Schedule)
	if err != nil {
		log.Printf("warn: bad schedule %q: %v", cfg.Schedule, err)
		return
	}
	loc := cfg.Location()
	for {
		now := time.Now().In(loc)
		next := time.Date(now.Year(), now.Month(), now.Day(), spec.hour, spec.minute, 0, 0, loc)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		d := time.Until(next)
		log.Printf("next scan scheduled at %s (in %s)", next.Format("2006-01-02 15:04"), d.Round(time.Minute))
		time.Sleep(d)

		// pick up schedule changes made in the panel
		if cur := holder.Get(); cur.Schedule != cfg.Schedule {
			if sp, err := parseDaily(cur.Schedule); err == nil {
				spec, cfg = sp, cur
				continue
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		if _, err := run(ctx, scan.Options{}); err != nil {
			log.Printf("scheduled scan failed: %v", err)
		}
		cancel()
		time.Sleep(time.Minute)
	}
}

type dailySpec struct{ hour, minute int }

// parseDaily understands "M H * * *" and "@daily".
func parseDaily(expr string) (dailySpec, error) {
	expr = strings.TrimSpace(expr)
	if expr == "@daily" || expr == "@midnight" {
		return dailySpec{hour: 4, minute: 0}, nil
	}
	f := strings.Fields(expr)
	if len(f) < 2 {
		return dailySpec{}, fmt.Errorf("expect at least 'minute hour'")
	}
	min, err := strconv.Atoi(f[0])
	if err != nil || min < 0 || min > 59 {
		return dailySpec{}, fmt.Errorf("bad minute %q", f[0])
	}
	hour, err := strconv.Atoi(f[1])
	if err != nil || hour < 0 || hour > 23 {
		return dailySpec{}, fmt.Errorf("bad hour %q", f[1])
	}
	return dailySpec{hour: hour, minute: min}, nil
}
