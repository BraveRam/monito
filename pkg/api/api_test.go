package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"monito/pkg/identity"
	"monito/pkg/storage"
)

type mockProvider struct{}

func (m *mockProvider) GetLiveStatus() LiveStatus {
	return LiveStatus{
		Timestamp:    time.Now(),
		TotalRateIn:  1024,
		TotalRateOut: 2048,
		TotalRate:    3072,
		AppRates: []LiveAppRate{
			{
				AppKey:      "exec:/usr/bin/curl",
				DisplayName: "curl",
				Category:    "cli_tool",
				RateIn:      1024,
				RateOut:     2048,
				TotalRate:   3072,
			},
		},
	}
}

func (m *mockProvider) GetCollectorStatus() CollectorStatus {
	return CollectorStatus{
		UptimeSeconds: 120,
		Version:       "1.0.0",
	}
}

func (m *mockProvider) GetDoctorReport() DoctorReport {
	return DoctorReport{
		KernelVersion:   "6.19.14",
		CgroupV2Mounted: true,
		BTFAvailable:    true,
	}
}

func TestAPIServerAndClient(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "monito-api-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	sockPath := filepath.Join(tmpDir, "test.sock")

	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ident := &identity.AppIdentity{
		AppKey:      "exec:/usr/bin/curl",
		DisplayName: "curl",
		Category:    "cli_tool",
	}
	_ = store.RecordUsage([]storage.IngestionRecord{
		{
			Identity: ident,
			Category: 2,
			BytesIn:  4096,
			BytesOut: 2048,
		},
	}, time.UTC)

	provider := &mockProvider{}
	server := NewServer(store, provider, sockPath)
	if err := server.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	defer server.Stop()

	// Wait briefly for listener
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	// Test GetSummary
	today := time.Now().UTC().Format("2006-01-02")
	summary, err := client.GetSummary(today)
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.TotalBytesIn != 4096 {
		t.Errorf("expected 4096 bytesIn, got %d", summary.TotalBytesIn)
	}

	// Test GetApps
	apps, err := client.GetApps(today, "total", "")
	if err != nil {
		t.Fatalf("GetApps failed: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].Identity.DisplayName != "curl" {
		t.Errorf("expected app 'curl', got %s", apps[0].Identity.DisplayName)
	}
	if apps[0].RateIn != 1024 {
		t.Errorf("expected rateIn 1024, got %f", apps[0].RateIn)
	}

	// Test GetLive
	live, err := client.GetLive()
	if err != nil {
		t.Fatalf("GetLive failed: %v", err)
	}
	if live.TotalRateIn != 1024 {
		t.Errorf("expected live totalRateIn 1024, got %f", live.TotalRateIn)
	}

	// Test GetStatus
	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status.UptimeSeconds != 120 {
		t.Errorf("expected uptime 120, got %d", status.UptimeSeconds)
	}

	// Test invalid date validation
	_, err = client.GetSummary("invalid-date")
	if err == nil {
		t.Error("expected error for invalid date, got nil")
	}
}

func TestDefaultSocketMatchesSystemService(t *testing.T) {
	t.Setenv("MONITO_SOCKET", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")
	if got := DefaultSocketPath(); got != "/run/monito/monito.sock" {
		t.Fatalf("system socket = %q", got)
	}
	t.Setenv("MONITO_SOCKET", "/tmp/custom.sock")
	if got := DefaultSocketPath(); got != "/tmp/custom.sock" {
		t.Fatalf("override = %q", got)
	}
}
