// Package store persists the latest scan report on disk.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"warpsub/internal/model"
)

// Store keeps the report in memory and mirrors it to JSON.
type Store struct {
	mu        sync.RWMutex
	hmu       sync.RWMutex
	path      string
	report    model.Report
	running   bool
	startedAt string
	history   []HistoryEntry
}

// New creates a store rooted at dir.
func New(dir string) *Store {
	return &Store{path: filepath.Join(dir, "report.json")}
}

// Load restores the last report, if any.
func (s *Store) Load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	s.mu.Lock()
	s.report = r
	s.mu.Unlock()
	return nil
}

// Save stores the report in memory and on disk.
func (s *Store) Save(r model.Report) error {
	s.mu.Lock()
	s.report = r
	s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

// Report returns the current report.
func (s *Store) Report() model.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.report
}

// SetRunning marks a scan in progress.
func (s *Store) SetRunning(v bool, startedAt string) {
	s.mu.Lock()
	s.running = v
	s.startedAt = startedAt
	s.mu.Unlock()
}

// State reports whether a scan is running.
func (s *Store) State() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running, s.startedAt
}

// HistoryLimit caps how many scan summaries are kept.
const HistoryLimit = 90

// HistoryEntry is one scan summary, kept for the trend view.
type HistoryEntry struct {
	At          string         `json:"at"`
	Candidates  int            `json:"candidates"`
	Passed      int            `json:"passed"`
	Counts      map[string]int `json:"counts"`
	BestLatency float64        `json:"best_latency_ms"`
	AvgLatency  float64        `json:"avg_latency_ms"`
	BestSpeed   float64        `json:"best_speed_mbps"`
	DurationSec float64        `json:"duration_sec"`
}

// LoadHistory restores the scan history.
func (s *Store) LoadHistory() ([]HistoryEntry, error) {
	raw, err := os.ReadFile(s.historyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var h []HistoryEntry
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	s.hmu.Lock()
	s.history = h
	s.hmu.Unlock()
	return h, nil
}

// AppendHistory adds one entry and persists the ring buffer.
func (s *Store) AppendHistory(e HistoryEntry) error {
	s.hmu.Lock()
	s.history = append(s.history, e)
	if len(s.history) > HistoryLimit {
		s.history = s.history[len(s.history)-HistoryLimit:]
	}
	raw, err := json.MarshalIndent(s.history, "", "  ")
	s.hmu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.historyPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.historyPath(), raw, 0o600)
}

// History returns a copy of the retained entries.
func (s *Store) History() []HistoryEntry {
	s.hmu.RLock()
	defer s.hmu.RUnlock()
	out := make([]HistoryEntry, len(s.history))
	copy(out, s.history)
	return out
}

func (s *Store) historyPath() string {
	return filepath.Join(filepath.Dir(s.path), "history.json")
}
