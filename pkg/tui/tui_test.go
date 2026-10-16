package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"monito/pkg/api"
	"monito/pkg/identity"
	"monito/pkg/storage"
)

func TestTUIViewAndKeyNavigation(t *testing.T) {
	client := api.NewClient("/dev/null")
	m := NewModel(client)
	m.width = 120
	m.height = 35

	// Populate model state directly
	m.connected = true
	m.summary = &storage.DaySummary{
		DayDate:        "2026-10-16",
		TotalBytesIn:   50 * 1024 * 1024,
		TotalBytesOut:  10 * 1024 * 1024,
		TotalBytes:     60 * 1024 * 1024,
		ExternalBytes:  55 * 1024 * 1024,
		PrivateBytes:   5 * 1024 * 1024,
		ActiveAppCount: 2,
	}

	m.apps = []api.AppUsageResponse{
		{
			AppID: 1,
			Identity: &identity.AppIdentity{
				AppKey:      "flatpak:org.mozilla.firefox",
				DisplayName: "Firefox",
				Category:    "web_browser",
			},
			BytesIn:    45 * 1024 * 1024,
			BytesOut:   5 * 1024 * 1024,
			TotalBytes: 50 * 1024 * 1024,
			RateIn:     10240,
			RateOut:    2048,
		},
		{
			AppID: 2,
			Identity: &identity.AppIdentity{
				AppKey:      "exec:/usr/bin/curl",
				DisplayName: "curl",
				Category:    "cli_tool",
			},
			BytesIn:    5 * 1024 * 1024,
			BytesOut:   5 * 1024 * 1024,
			TotalBytes: 10 * 1024 * 1024,
		},
	}

	m.live = &api.LiveStatus{
		Timestamp:    time.Now(),
		TotalRateIn:  10240,
		TotalRateOut: 2048,
		TotalRate:    12288,
	}

	// 1. Test normal dashboard view rendering
	view := m.View()
	if !strings.Contains(view, "MONITO") {
		t.Errorf("expected view to contain 'MONITO', got:\n%s", view)
	}
	if !strings.Contains(view, "Firefox") {
		t.Errorf("expected view to contain 'Firefox', got:\n%s", view)
	}
	if !strings.Contains(view, "DAY VOLUME") {
		t.Errorf("expected view to contain 'DAY VOLUME', got:\n%s", view)
	}

	// 2. Test Down arrow navigation
	updatedModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updatedModel.(Model)
	if m.selectedIndex != 1 {
		t.Errorf("expected selectedIndex 1, got %d", m.selectedIndex)
	}

	// 3. Test Enter to open Detail View
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)
	if !m.detailView {
		t.Error("expected detailView to be true after Enter")
	}
	detailView := m.View()
	if !strings.Contains(detailView, "7-Day Usage History") {
		t.Errorf("expected detail view to contain '7-Day Usage History', got:\n%s", detailView)
	}

	// 4. Test Esc to return to Dashboard
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(Model)
	if m.detailView {
		t.Error("expected detailView to be false after Esc")
	}

	// 5. Test Help Modal (?)
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = updatedModel.(Model)
	if !m.showHelp {
		t.Error("expected showHelp to be true after '?'")
	}
	helpView := m.View()
	if !strings.Contains(helpView, "KEYBOARD SHORTCUTS") {
		t.Errorf("expected help view to contain 'KEYBOARD SHORTCUTS', got:\n%s", helpView)
	}

	// 6. Test Esc to close help
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updatedModel.(Model)
	if m.showHelp {
		t.Error("expected showHelp to be false after Esc")
	}

	// 7. Test Disconnected View
	m.connected = false
	discView := m.View()
	if !strings.Contains(discView, "COLLECTOR DISCONNECTED") {
		t.Errorf("expected disconnected view, got:\n%s", discView)
	}
}

func TestTUIResizeHandling(t *testing.T) {
	client := api.NewClient("/dev/null")
	m := NewModel(client)

	updatedModel, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = updatedModel.(Model)
	if m.width != 80 || m.height != 24 {
		t.Errorf("expected width 80 height 24, got %dx%d", m.width, m.height)
	}

	updatedModel, _ = m.Update(tea.WindowSizeMsg{Width: 160, Height: 50})
	m = updatedModel.(Model)
	if m.width != 160 || m.height != 50 {
		t.Errorf("expected width 160 height 50, got %dx%d", m.width, m.height)
	}
}

func TestStaleResponsesAndModalQuit(t *testing.T) {
	m := NewModel(api.NewClient("/dev/null"))
	oldQuery := m.currentQuery()
	m.currentDate = m.currentDate.AddDate(0, 0, -1)
	updated, _ := m.Update(dataRefreshMsg{query: oldQuery, started: time.Now(), summary: &storage.DaySummary{TotalBytes: 999}})
	m = updated.(Model)
	if m.summary != nil {
		t.Fatal("stale date response applied")
	}
	newest := time.Now()
	updated, _ = m.Update(dataRefreshMsg{query: m.currentQuery(), started: newest, summary: &storage.DaySummary{TotalBytes: 10}})
	m = updated.(Model)
	updated, _ = m.Update(dataRefreshMsg{query: m.currentQuery(), started: newest.Add(-time.Second), summary: &storage.DaySummary{TotalBytes: 999}})
	m = updated.(Model)
	if m.summary.TotalBytes != 10 {
		t.Fatal("older response overwrote newer data")
	}
	m.detailView = true
	m.detailApp = &api.AppUsageResponse{Identity: &identity.AppIdentity{AppKey: "app:B"}}
	updated, _ = m.Update(historyRefreshMsg{appKey: "app:A", history: []storage.AppHistoryPoint{{TotalBytes: 999}}})
	m = updated.(Model)
	if len(m.detailHistory) != 0 {
		t.Fatal("wrong application's history applied")
	}
	for _, state := range []string{"detail", "help", "filter"} {
		m.detailView, m.showHelp, m.filtering = state == "detail", state == "help", state == "filter"
		_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if cmd == nil {
			t.Fatalf("Ctrl+C ignored in %s", state)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("Ctrl+C did not quit in %s", state)
		}
	}
}
