package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"monito/pkg/api"
	"monito/pkg/storage"
	"monito/pkg/util"
)

func (m Model) View() string {
	if m.width == 0 {
		m.width = 100
	}
	if m.height == 0 {
		m.height = 30
	}

	if !m.connected {
		return m.renderDisconnectedView()
	}

	if m.showHelp {
		return m.renderHelpModal()
	}

	if m.detailView && m.detailApp != nil {
		return m.renderDetailModal()
	}

	var b strings.Builder

	// 1. Header Banner
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// 2. Metrics Cards
	b.WriteString(m.renderCards())
	b.WriteString("\n")

	b.WriteString(m.renderCoverage())
	b.WriteString("\n")

	// 3. Search & Filter Bar / Active Date
	b.WriteString(m.renderControls())
	b.WriteString("\n")

	// 4. Main Applications Table
	b.WriteString(m.renderTable())
	b.WriteString("\n")

	// 5. Status Footer & Key Hints
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m Model) renderHeader() string {
	title := titleStyle.Render(" MONITO ")
	sub := mutedText.Render(" Linux Network Traffic Monitor")
	if m.width < 105 {
		sub = ""
	}

	dateBadge := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#3A3A4C")).
		Padding(0, 1).
		Render(fmt.Sprintf(" 📅 %s ", m.currentDate.Format("Mon Jan 02, 2006")))

	collectorBadge := lipgloss.NewStyle().Foreground(secondaryColor).Render("● Collector Active")
	if m.collectorStatus != nil && m.collectorStatus.MapErrors > 0 {
		collectorBadge += lipgloss.NewStyle().Foreground(warningColor).Render(fmt.Sprintf(" (⚠️ %d drops)", m.collectorStatus.MapErrors))
	}

	gapWidth := m.width - lipgloss.Width(title) - lipgloss.Width(sub) - lipgloss.Width(dateBadge) - lipgloss.Width(collectorBadge) - 6
	if gapWidth < 2 {
		gapWidth = 2
	}
	gap := strings.Repeat(" ", gapWidth)

	return lipgloss.JoinHorizontal(lipgloss.Center, title, sub, gap, dateBadge, " ", collectorBadge)
}

func (m Model) renderCards() string {
	cardWidth := (m.width - 8) / 3
	if cardWidth < 20 {
		cardWidth = 20
	}
	summary := m.summary
	if summary == nil {
		summary = &storage.DaySummary{}
	}
	live := m.live
	if live == nil {
		live = &api.LiveStatus{}
	}
	transferring := 0
	for _, rate := range live.AppRates {
		if !strings.HasPrefix(rate.AppKey, "unknown:") && rate.TotalRate > 0 {
			transferring++
		}
	}
	volume := fmt.Sprintf("%s %s\nDownload: %s\nUpload:   %s\nRecorded: %d apps",
		headerLabel.Render("Total:"), headerValue.Render(util.FormatBytes(summary.TotalBytes)),
		util.FormatBytes(summary.TotalBytesIn), util.FormatBytes(summary.TotalBytesOut), summary.RecordedAppCount)
	speed := fmt.Sprintf("%s %s\nInflow:  %s\nOutflow: %s\nTransferring: %d apps", headerLabel.Render("Current:"),
		headerValue.Render(util.FormatRate(live.TotalRate)), util.FormatRate(live.TotalRateIn), util.FormatRate(live.TotalRateOut), transferring)
	pct := func(bytes int64) float64 {
		if summary.TotalBytes == 0 {
			return 0
		}
		return float64(bytes) * 100 / float64(summary.TotalBytes)
	}
	mix := fmt.Sprintf("External: %.1f%%\nLAN/Priv: %.1f%%\nLoopback: %.1f%%\nUnknown:  %.1f%%",
		pct(summary.ExternalBytes), pct(summary.PrivateBytes), pct(summary.LoopbackBytes), pct(summary.UnknownBytes))
	cards := []string{}
	for _, card := range []struct{ title, body string }{{"DAY VOLUME", volume}, {"LIVE SPEED", speed}, {"TRAFFIC MIX", mix}} {
		cards = append(cards, cardStyle.Width(cardWidth).Render(headerLabel.Render(card.title)+"\n"+card.body))
	}
	if m.width < 72 {
		return lipgloss.JoinVertical(lipgloss.Left, cards...)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, cards[0], " ", cards[1], " ", cards[2])
}

func (m Model) renderCoverage() string {
	text := "App attribution: no recorded traffic"
	if m.summary != nil && m.summary.TotalBytes > 0 {
		attributed := m.summary.TotalBytes - m.summary.UnattributedBytes
		text = fmt.Sprintf("App attribution: %.1f%% | Unattributed: %s", float64(attributed)*100/float64(m.summary.TotalBytes), util.FormatBytes(m.summary.UnattributedBytes))
		if m.summary.UnattributedBytes > 0 {
			text += "\nUnattributed means no confirmed app owner; old bytes cannot be assigned retroactively."
		}
	}
	if status := m.collectorStatus; status != nil {
		text += fmt.Sprintf(" | Existing sockets recovered: %d", status.RecoveredSockets)
		if status.RecoveryErrors > 0 {
			text += " (recovery failures; see monito doctor)"
		}
	}
	return lipgloss.NewStyle().Width(m.width).Foreground(mutedColor).Render(text)
}

func (m Model) renderControls() string {
	dateNav := fmt.Sprintf(
		"%s [←/→ or h/l] %s",
		mutedText.Render("Date:"),
		headerValue.Render(m.currentDate.Format("2006-01-02")),
	)
	if m.currentDate.Format("2006-01-02") == time.Now().Format("2006-01-02") {
		dateNav += lipgloss.NewStyle().Foreground(secondaryColor).Render(" (Today)")
	}

	sortIndicator := fmt.Sprintf("%s %s", mutedText.Render("Sort:"), headerLabel.Render(m.sortBy))

	var searchBox string
	if m.filtering {
		searchBox = m.filterInput.View()
	} else if m.filterText != "" {
		searchBox = fmt.Sprintf("🔍 Filter: %s [press 'c' to clear]", headerLabel.Render(m.filterText))
	} else {
		searchBox = mutedText.Render("Press [/] to filter apps")
	}

	return lipgloss.NewStyle().Width(m.width).Render(fmt.Sprintf("%s   │   %s   │   %s", dateNav, sortIndicator, searchBox))
}

func (m Model) renderTable() string {
	showType := m.width >= 115
	numberWidth := 10
	if m.width >= 115 {
		numberWidth = 13
	}
	typeWidth := 0
	gaps := 4
	if showType {
		typeWidth = 14
		gaps = 5
	}
	colApp := m.width - 2 - gaps - typeWidth - 4*numberWidth
	if colApp > 32 {
		colApp = 32
	}
	if colApp < 12 {
		colApp = 12
	}
	cell := func(value string, width int, right bool) string {
		style := lipgloss.NewStyle().Width(width).MaxWidth(width)
		if right {
			style = style.Align(lipgloss.Right)
		}
		return style.Render(ansi.Truncate(value, width, "…"))
	}
	formatRow := func(app, kind, down, up, total, rate string) string {
		cells := []string{cell(app, colApp, false)}
		if showType {
			cells = append(cells, cell(kind, typeWidth, false))
		}
		for _, value := range []string{down, up, total, rate} {
			cells = append(cells, cell(value, numberWidth, true))
		}
		return strings.Join(cells, " ")
	}
	headerLine := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#2E2E3E")).Render(
		"  " + formatRow("APPLICATION", "APP TYPE", "DOWNLOAD", "UPLOAD", "TOTAL", "RATE"))

	var rows []string
	rows = append(rows, headerLine)

	if len(m.apps) == 0 {
		emptyMsg := "  (No network activity recorded for this date / filter)"
		rows = append(rows, mutedText.Render(emptyMsg))
	} else {
		// Available vertical space for table rows
		maxRows := m.height - lipgloss.Height(m.renderHeader()) - lipgloss.Height(m.renderCards()) -
			lipgloss.Height(m.renderCoverage()) - lipgloss.Height(m.renderControls()) - lipgloss.Height(m.renderFooter()) - 1
		if maxRows < 1 {
			maxRows = 1
		}

		// Calculate window scroll offset
		startIdx := 0
		if m.selectedIndex >= maxRows {
			startIdx = m.selectedIndex - maxRows + 1
		}
		endIdx := startIdx + maxRows
		if endIdx > len(m.apps) {
			endIdx = len(m.apps)
		}

		for i := startIdx; i < endIdx; i++ {
			app := m.apps[i]
			isSel := (i == m.selectedIndex)

			// Icon prefix
			icon := "⚙"
			switch app.Identity.Category {
			case "web_browser":
				icon = "🌐"
			case "desktop_app":
				icon = "📦"
			case "cli_tool":
				icon = "⚡"
			case "system_service":
				icon = "🛠"
			}

			appName := fmt.Sprintf("%s %s", icon, app.Identity.DisplayName)

			rateStr := "-"
			if app.RateIn+app.RateOut > 0 {
				rateStr = util.FormatRate(app.RateIn + app.RateOut)
			}

			rowStr := formatRow(appName, app.Identity.Category, util.FormatBytes(app.BytesIn), util.FormatBytes(app.BytesOut), util.FormatBytes(app.TotalBytes), rateStr)

			if isSel {
				rowStr = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("#FFFFFF")).
					Background(lipgloss.Color("#4338CA")).
					Render("▶ " + rowStr)
			} else {
				rowStr = "  " + rowStr
			}

			rows = append(rows, rowStr)
		}
	}

	return strings.Join(rows, "\n")
}

func (m Model) renderFooter() string {
	keys := []string{
		"[q] Quit",
		"[/] Filter",
		"[s/t] Total",
		"[d] Down",
		"[u] Up",
		"[r] Rate",
		"[←/→] Day",
		"[Enter] Details",
		"[?] Help",
	}

	hintStr := strings.Join(keys, "  ")
	return lipgloss.NewStyle().Width(m.width).Foreground(mutedColor).Render(hintStr)
}

func (m Model) renderDisconnectedView() string {
	msg := fmt.Sprintf(`
%s

Cannot connect to Monito collector socket at:
  %s

%s
  • The background collector is not running.
  • Or permissions restrict access to the socket.

%s
  • If installed as a system service:
      sudo systemctl start monito
  • Or start the collector locally:
      ./monitod
  • To run doctor diagnostics:
      ./monito doctor

Retrying connection every 1s... (Press 'q' or Ctrl+C to quit)
`,
		lipgloss.NewStyle().Bold(true).Foreground(errorColor).Render("⚠️  COLLECTOR DISCONNECTED"),
		headerValue.Render(api.DefaultSocketPath()),
		headerLabel.Render("Possible Causes:"),
		headerLabel.Render("How to Resolve:"),
	)

	box := disconnectedBox.Width(m.width - 8).Render(msg)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m Model) renderDetailModal() string {
	app := m.detailApp
	if app == nil {
		return ""
	}

	var histLines []string
	if len(m.detailHistory) == 0 {
		histLines = append(histLines, "  (Loading history or no previous days recorded)")
	} else {
		histLines = append(histLines, "  Date        | Inflow       | Outflow      | Total")
		histLines = append(histLines, "  ------------+--------------+--------------+-------------")
		for _, pt := range m.detailHistory {
			histLines = append(histLines, fmt.Sprintf(
				"  %-11s | %-12s | %-12s | %s",
				pt.Date,
				util.FormatBytes(pt.BytesIn),
				util.FormatBytes(pt.BytesOut),
				util.FormatBytes(pt.TotalBytes),
			))
		}
	}

	content := fmt.Sprintf(`
%s: %s

%s %s
%s %s
%s %s
%s %s
%s %s

%s
%s

%s
`,
		headerLabel.Render("Application"), headerValue.Render(app.Identity.DisplayName),
		mutedText.Render("App Key:       "), app.Identity.AppKey,
		mutedText.Render("Category:      "), app.Identity.Category,
		mutedText.Render("Executable:    "), app.Identity.ExecutablePath,
		mutedText.Render("cgroup v2:     "), app.Identity.CgroupPath,
		mutedText.Render("First Seen:    "), app.Identity.FirstSeen.Format("2006-01-02 15:04:05 UTC"),
		headerLabel.Render("7-Day Usage History:"),
		strings.Join(histLines, "\n"),
		lipgloss.NewStyle().Foreground(accentColor).Render("Press [Esc] or [Enter] to return to dashboard"),
	)

	modal := modalBox.Width(m.width - 10).Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
}

func (m Model) renderHelpModal() string {
	helpText := fmt.Sprintf(`
%s

%s  Navigate up/down through applications list
%s  Open application details and 7-day history
%s  Step backward / forward through calendar days
%s  Reset date to Today
%s  Activate live interactive search / filter
%s  Clear active search filter
%s  Sort applications by Total Volume
%s  Sort applications by Download (Inflow)
%s  Sort applications by Upload (Outflow)
%s  Sort applications by Current Bandwidth Rate
%s  Sort applications alphabetically by Name
%s  Toggle this help overlay
%s  Exit Monito

%s
`,
		titleStyle.Render(" KEYBOARD SHORTCUTS "),
		helpKeyStyle.Render("↑ / ↓ or k / j:"),
		helpKeyStyle.Render("Enter:         "),
		helpKeyStyle.Render("← / → or h / l:"),
		helpKeyStyle.Render("T:             "),
		helpKeyStyle.Render("/:             "),
		helpKeyStyle.Render("c:             "),
		helpKeyStyle.Render("s or t:        "),
		helpKeyStyle.Render("d:             "),
		helpKeyStyle.Render("u:             "),
		helpKeyStyle.Render("r:             "),
		helpKeyStyle.Render("n:             "),
		helpKeyStyle.Render("?:             "),
		helpKeyStyle.Render("q or Ctrl+C:   "),
		lipgloss.NewStyle().Foreground(accentColor).Render("Press [Esc] or [?] to close help"),
	)

	modal := modalBox.Width(m.width - 12).Render(helpText)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal)
}
