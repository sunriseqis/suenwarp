// Package stability tracks how many consecutive scans a candidate survived, so
// a subscription can require a node to prove itself instead of trusting a single
// measurement.
package stability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"warpsub/internal/model"
)

// Store keeps the per-candidate streak counters.
type Store struct {
	mu   sync.Mutex
	path string
	data data
}

type data struct {
	// Recent holds the key sets of the most recent scans, newest last.
	Recent []scanSet `json:"recent"`
	Scans  int       `json:"scans"`
}

type scanSet struct {
	Keys []string `json:"keys"`
}

// New loads data/stability.json.
func New(dir string) *Store {
	s := &Store{path: filepath.Join(dir, "stability.json")}
	if raw, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(raw, &s.data)
	}
	return s
}

// Key identifies a node across scans.
func Key(n model.Node) string {
	return n.Class + "|" + n.Server + "|" + itoa(n.Port)
}

// Apply records this scan and returns the subset that appeared in at least
// minHits of the recent scans.
//
// A sliding window is used instead of a strict consecutive streak: one bad scan
// (throttling, a transient network hiccup) should not wipe the subscription.
func (s *Store) Apply(nodes []model.Node, minHits int, bootstrap bool) (keep []model.Node, hits map[string]int, fellBack bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if minHits < 1 {
		minHits = 1
	}
	window := minHits
	if window < 3 {
		window = 3
	}
	if window > 10 {
		window = 10
	}

	// count how often each key showed up in the retained window
	hits = make(map[string]int, len(nodes))
	cur := scanSet{Keys: make([]string, 0, len(nodes))}
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		k := Key(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		cur.Keys = append(cur.Keys, k)
	}

	for _, set := range s.data.Recent {
		for _, k := range set.Keys {
			if seen[k] {
				hits[k]++
			}
		}
	}
	for k := range seen {
		hits[k]++ // count the current scan
	}

	for _, n := range nodes {
		if hits[Key(n)] >= minHits {
			keep = append(keep, n)
		}
	}

	s.data.Recent = append(s.data.Recent, cur)
	if len(s.data.Recent) > window {
		s.data.Recent = s.data.Recent[len(s.data.Recent)-window:]
	}
	s.data.Scans++
	s.persistLocked()

	if len(keep) == 0 && bootstrap && len(nodes) > 0 {
		return nodes, hits, true
	}
	return keep, hits, false
}

func (s *Store) persistLocked() {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	_ = os.WriteFile(s.path, raw, 0o600)
}

// Scans reports how many scans have been recorded.
func (s *Store) Scans() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Scans
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
