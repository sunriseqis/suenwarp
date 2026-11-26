package scoring

import (
	"fmt"
	"math"

	"warpsub/internal/config"
	"warpsub/internal/model"
)

// Weights once real throughput is known. Latency is only a tiebreaker: what a
// user feels when pulling a container image or holding a chat session is how
// fast and how steadily the bytes flow, not the first round trip.
const (
	wSpeed     = 0.45
	wStability = 0.45
	wLatency   = 0.10
)

// Weights before throughput is measured, for the provisional ranking that
// decides who gets the download test at all.
const (
	wPLatency = 0.55
	wPJitter  = 0.25
	wPLoss    = 0.20
)

// Evaluate applies the hard thresholds and computes the composite score.
func Evaluate(n *model.Node, t config.Thresh, hasSpeed bool) (float64, bool, string) {
	if n.LatencyMS <= 0 {
		return 0, false, "无响应"
	}
	maxLat := t.MaxLatencyMS
	if n.Class == model.ClassMasque && t.MasqueMaxLatencyMS > 0 {
		maxLat = t.MasqueMaxLatencyMS
	}
	if maxLat > 0 && n.LatencyMS > maxLat {
		return 0, false, fmt.Sprintf("延迟 %.0fms 超过存活阈值 %.0fms", n.LatencyMS, maxLat)
	}
	if t.MaxLossPct > 0 && n.LossPct > t.MaxLossPct {
		return 0, false, fmt.Sprintf("丢包 %.0f%% 超过阈值 %.0f%%", n.LossPct, t.MaxLossPct)
	}

	lat := normInv(n.LatencyMS, maxLat)

	if !hasSpeed {
		jit := normInv(n.JitterMS, nonZero(t.MaxJitterMS, 100))
		loss := 100 * (1 - clamp(n.LossPct/100, 0, 1))
		return round1(lat*wPLatency + jit*wPJitter + loss*wPLoss), true, ""
	}

	if t.MinSpeedMbps > 0 && n.SpeedMbps < t.MinSpeedMbps {
		return 0, false, fmt.Sprintf("速率 %.1fMbps 低于门槛 %.1fMbps", n.SpeedMbps, t.MinSpeedMbps)
	}
	if t.MinStability > 0 && n.Stability < t.MinStability {
		return 0, false, fmt.Sprintf("稳定性 %.0f 低于门槛 %.0f（衰减 %.0f%%/抖动 CV %.2f/卡顿 %.0f%%）",
			n.Stability, t.MinStability, decayPct(n), n.SpeedCV, n.StallPct)
	}

	ref := t.SpeedRefMbps
	if ref <= 0 {
		ref = 50
	}
	spd := clamp(n.SpeedMbps/ref, 0, 1) * 100
	return round1(spd*wSpeed + n.Stability*wStability + lat*wLatency), true, ""
}

func decayPct(n *model.Node) float64 {
	if n.SpeedPeak <= 0 {
		return 0
	}
	return 100 * (1 - n.SpeedTail/n.SpeedPeak)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func normInv(v, max float64) float64 {
	if max <= 0 {
		max = 1
	}
	return clamp(1-v/max, 0, 1) * 100
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func nonZero(v, def float64) float64 {
	if v <= 0 {
		return def
	}
	return v
}
