package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/BraveRam/monito/pkg/api"
	"github.com/BraveRam/monito/pkg/storage"
)

type tickMsg time.Time
type dataQuery struct{ date, sort, filter string }
type dataRefreshMsg struct {
	query   dataQuery
	started time.Time
	summary *storage.DaySummary
	apps    []api.AppUsageResponse
	live    *api.LiveStatus
	status  *api.CollectorStatus
	err     error
}
type historyRefreshMsg struct {
	appKey  string
	history []storage.AppHistoryPoint
	err     error
}

// Model is the main Bubble Tea model for the Monito TUI
type Model struct {
	client          *api.Client
	currentDate     time.Time
	summary         *storage.DaySummary
	apps            []api.AppUsageResponse
	live            *api.LiveStatus
	collectorStatus *api.CollectorStatus
	connected       bool
	lastErr         error
	lastRefresh     time.Time

	sortBy      string // "total", "download", "upload", "rate", "name"
	filterInput textinput.Model
	filtering   bool
	filterText  string

	selectedIndex int
	scrollOffset  int

	detailView    bool
	detailApp     *api.AppUsageResponse
	detailHistory []storage.AppHistoryPoint

	showHelp bool
	width    int
	height   int
}

// NewModel creates an initialized TUI model
func NewModel(client *api.Client) Model {
	ti := textinput.New()
	ti.Placeholder = "filter apps (e.g. firefox, curl, systemd)..."
	ti.CharLimit = 32
	ti.Width = 36

	return Model{
		client:        client,
		currentDate:   time.Now(),
		sortBy:        "total",
		filterInput:   ti,
		selectedIndex: 0,
		connected:     false,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.fetchDataCmd(),
		m.tickCmd(),
	)
}

func (m Model) tickCmd() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) fetchDataCmd() tea.Cmd {
	query := m.currentQuery()
	started := time.Now()
	return func() tea.Msg {
		msg := dataRefreshMsg{query: query, started: started}
		msg.summary, msg.err = m.client.GetSummary(query.date)
		if msg.err != nil {
			return msg
		}
		msg.apps, msg.err = m.client.GetApps(query.date, query.sort, query.filter)
		if msg.err != nil {
			return msg
		}
		msg.live, _ = m.client.GetLive()
		msg.status, _ = m.client.GetStatus()
		return msg
	}
}

func (m Model) currentQuery() dataQuery {
	return dataQuery{m.currentDate.Format("2006-01-02"), m.sortBy, m.filterText}
}

func (m Model) fetchHistoryCmd(appKey string) tea.Cmd {
	return func() tea.Msg {
		history, err := m.client.GetHistory(appKey, 7)
		return historyRefreshMsg{
			appKey:  appKey,
			history: history,
			err:     err,
		}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		cmds = append(cmds, m.fetchDataCmd(), m.tickCmd())

	case dataRefreshMsg:
		if msg.query != m.currentQuery() || msg.started.Before(m.lastRefresh) {
			return m, nil
		}
		m.lastRefresh = msg.started
		if msg.err != nil {
			m.connected = false
			m.lastErr = msg.err
		} else {
			m.connected = true
			m.lastErr = nil
			m.summary = msg.summary
			m.apps = msg.apps
			m.live = msg.live
			m.collectorStatus = msg.status

			// Clamp selection
			if len(m.apps) == 0 {
				m.selectedIndex = 0
			} else if m.selectedIndex >= len(m.apps) {
				m.selectedIndex = len(m.apps) - 1
			}
		}

	case historyRefreshMsg:
		if m.detailView && m.detailApp != nil && msg.appKey == m.detailApp.Identity.AppKey && msg.err == nil {
			m.detailHistory = msg.history
		}

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.filtering {
			switch msg.String() {
			case "enter":
				m.filtering = false
				m.filterText = strings.TrimSpace(m.filterInput.Value())
				cmds = append(cmds, m.fetchDataCmd())
				return m, tea.Batch(cmds...)
			case "esc":
				m.filtering = false
				m.filterInput.SetValue("")
				m.filterText = ""
				cmds = append(cmds, m.fetchDataCmd())
				return m, tea.Batch(cmds...)
			default:
				var cmd tea.Cmd
				m.filterInput, cmd = m.filterInput.Update(msg)
				m.filterText = strings.TrimSpace(m.filterInput.Value())
				cmds = append(cmds, cmd, m.fetchDataCmd())
				return m, tea.Batch(cmds...)
			}
		}

		if m.detailView {
			switch msg.String() {
			case "esc", "q", "enter", "backspace":
				m.detailView = false
				m.detailApp = nil
				m.detailHistory = nil
				return m, nil
			}
			return m, nil
		}

		if m.showHelp {
			switch msg.String() {
			case "esc", "q", "?", "enter":
				m.showHelp = false
				return m, nil
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "/":
			m.filtering = true
			m.filterInput.Focus()
			return m, textinput.Blink

		case "?":
			m.showHelp = !m.showHelp
			return m, nil

		case "up", "k":
			if m.selectedIndex > 0 {
				m.selectedIndex--
			}

		case "down", "j":
			if m.selectedIndex < len(m.apps)-1 {
				m.selectedIndex++
			}

		case "enter":
			if len(m.apps) > 0 && m.selectedIndex < len(m.apps) {
				selected := m.apps[m.selectedIndex]
				m.detailView = true
				m.detailApp = &selected
				m.detailHistory = nil
				cmds = append(cmds, m.fetchHistoryCmd(selected.Identity.AppKey))
				return m, tea.Batch(cmds...)
			}

		case "s", "t":
			m.sortBy = "total"
			cmds = append(cmds, m.fetchDataCmd())

		case "u":
			m.sortBy = "upload"
			cmds = append(cmds, m.fetchDataCmd())

		case "d":
			m.sortBy = "download"
			cmds = append(cmds, m.fetchDataCmd())

		case "r":
			m.sortBy = "rate"
			cmds = append(cmds, m.fetchDataCmd())

		case "n":
			m.sortBy = "name"
			cmds = append(cmds, m.fetchDataCmd())

		case "left", "h", "[":
			// Previous day
			m.currentDate = m.currentDate.AddDate(0, 0, -1)
			cmds = append(cmds, m.fetchDataCmd())

		case "right", "l", "]":
			// Next day (not exceeding today)
			next := m.currentDate.AddDate(0, 0, 1)
			if !next.After(time.Now()) {
				m.currentDate = next
				cmds = append(cmds, m.fetchDataCmd())
			}

		case "T":
			// Reset to today
			m.currentDate = time.Now()
			cmds = append(cmds, m.fetchDataCmd())

		case "c":
			// Clear filter
			m.filterInput.SetValue("")
			m.filterText = ""
			cmds = append(cmds, m.fetchDataCmd())
		}
	}

	return m, tea.Batch(cmds...)
}
