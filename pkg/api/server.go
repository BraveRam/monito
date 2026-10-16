package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"monito/pkg/storage"
)

// DataProvider supplies live rates, collector diagnostics, and doctor checks to the API server
type DataProvider interface {
	GetLiveStatus() LiveStatus
	GetCollectorStatus() CollectorStatus
	GetDoctorReport() DoctorReport
}

// Server provides the HTTP-over-UDS versioned API
type Server struct {
	mu         sync.Mutex
	store      *storage.Storage
	provider   DataProvider
	socketPath string
	listener   net.Listener
	httpServer *http.Server
}

// NewServer creates a new API server instance
func NewServer(store *storage.Storage, provider DataProvider, socketPath string) *Server {
	return &Server{
		store:      store,
		provider:   provider,
		socketPath: socketPath,
	}
}

// Start listens on the Unix socket and serves API requests
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	// Remove stale socket if exists
	_ = os.Remove(s.socketPath)

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket %s: %w", s.socketPath, err)
	}

	// This API is read-only and intentionally available to local users.
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		_ = l.Close()
		return fmt.Errorf("set socket permissions: %w", err)
	}

	s.listener = l

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/summary", s.handleSummary)
	mux.HandleFunc("/api/v1/apps", s.handleApps)
	mux.HandleFunc("/api/v1/history", s.handleHistory)
	mux.HandleFunc("/api/v1/live", s.handleLive)
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/doctor", s.handleDoctor)

	// Wrap mux with request body limit middleware (max 64KB)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	})

	s.httpServer = &http.Server{
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		_ = s.httpServer.Serve(l)
	}()

	return nil
}

// Stop shuts down the API server and removes the socket file
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
	return nil
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	date := r.URL.Query().Get("date")
	if date == "" {
		date = time.Now().Format("2006-01-02")
	} else if _, err := time.Parse("2006-01-02", date); err != nil {
		http.Error(w, `{"error":"invalid date format, must be YYYY-MM-DD"}`, http.StatusBadRequest)
		return
	}

	summary, err := s.store.GetDaySummary(date)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to get summary: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	date := r.URL.Query().Get("date")
	if date == "" {
		date = time.Now().Format("2006-01-02")
	} else if _, err := time.Parse("2006-01-02", date); err != nil {
		http.Error(w, `{"error":"invalid date format, must be YYYY-MM-DD"}`, http.StatusBadRequest)
		return
	}

	sort := r.URL.Query().Get("sort")
	filter := strings.ToLower(r.URL.Query().Get("filter"))

	records, err := s.store.GetAppsForDay(date, sort)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to get apps: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Fetch current rates to attach to apps
	live := s.provider.GetLiveStatus()
	aliases, err := s.store.CanonicalKeys()
	if err != nil {
		http.Error(w, `{"error":"failed to resolve application aliases"}`, http.StatusInternalServerError)
		return
	}
	rateMap := make(map[string]LiveAppRate)
	for _, appRate := range live.AppRates {
		key := appRate.AppKey
		if canonical := aliases[key]; canonical != "" {
			key = canonical
		}
		rate := rateMap[key]
		rate.RateIn += appRate.RateIn
		rate.RateOut += appRate.RateOut
		rateMap[key] = rate
	}

	var resp []AppUsageResponse
	for _, rec := range records {
		ident := rec.Identity
		if filter != "" {
			match := strings.Contains(strings.ToLower(ident.DisplayName), filter) ||
				strings.Contains(strings.ToLower(ident.AppKey), filter) ||
				strings.Contains(strings.ToLower(ident.Category), filter)
			if !match {
				continue
			}
		}

		item := AppUsageResponse{
			AppID:       rec.AppID,
			Identity:    rec.Identity,
			Category:    rec.Category,
			CategoryStr: rec.CategoryStr,
			BytesIn:     rec.BytesIn,
			BytesOut:    rec.BytesOut,
			TotalBytes:  rec.TotalBytes,
			PacketsIn:   rec.PacketsIn,
			PacketsOut:  rec.PacketsOut,
		}

		if ar, ok := rateMap[ident.AppKey]; ok && date == time.Now().Format("2006-01-02") {
			item.RateIn = ar.RateIn
			item.RateOut = ar.RateOut
		}

		resp = append(resp, item)
	}

	// If sorted by rate, sort here
	if sort == "rate" {
		// Simple bubble sort or stable sort
		for i := 0; i < len(resp)-1; i++ {
			for j := i + 1; j < len(resp); j++ {
				rateI := resp[i].RateIn + resp[i].RateOut
				rateJ := resp[j].RateIn + resp[j].RateOut
				if rateJ > rateI {
					resp[i], resp[j] = resp[j], resp[i]
				}
			}
		}
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	appKey := r.URL.Query().Get("app")
	if appKey == "" {
		http.Error(w, `{"error":"app parameter is required"}`, http.StatusBadRequest)
		return
	}

	daysStr := r.URL.Query().Get("days")
	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		} else {
			http.Error(w, `{"error":"days must be an integer between 1 and 365"}`, http.StatusBadRequest)
			return
		}
	}

	pts, err := s.store.GetAppHistory(appKey, days)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to get history: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(pts)
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	live := s.provider.GetLiveStatus()
	aliases, err := s.store.CanonicalKeys()
	if err != nil {
		http.Error(w, `{"error":"failed to resolve application aliases"}`, http.StatusInternalServerError)
		return
	}
	live = groupLiveRates(live, aliases)
	_ = json.NewEncoder(w).Encode(live)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := s.provider.GetCollectorStatus()
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	doctor := s.provider.GetDoctorReport()
	_ = json.NewEncoder(w).Encode(doctor)
}

func groupLiveRates(live LiveStatus, aliases map[string]string) LiveStatus {
	grouped := make(map[string]LiveAppRate)
	for _, rate := range live.AppRates {
		if key := aliases[rate.AppKey]; key != "" {
			rate.AppKey = key
		}
		current := grouped[rate.AppKey]
		current.AppKey, current.DisplayName, current.Category = rate.AppKey, rate.DisplayName, rate.Category
		current.RateIn += rate.RateIn
		current.RateOut += rate.RateOut
		current.TotalRate = current.RateIn + current.RateOut
		grouped[rate.AppKey] = current
	}
	live.AppRates = nil
	for _, rate := range grouped {
		live.AppRates = append(live.AppRates, rate)
	}
	sort.Slice(live.AppRates, func(i, j int) bool { return live.AppRates[i].TotalRate > live.AppRates[j].TotalRate })
	return live
}
