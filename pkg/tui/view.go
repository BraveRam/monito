package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"monito/pkg/api"
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
	cardWidth := (m.width - 6) / 3
	if cardWidth < 26 {
		cardWidth = 26
	}

	// Card 1: Today's Volume
	var totalIn, totalOut, totalBytes int64
	if m.summary != nil {
		totalIn = m.summary.TotalBytesIn
		totalOut = m.summary.TotalBytesOut
		totalBytes = m.summary.TotalBytes
	}

	volContent := fmt.Sprintf(
		"%s %s\n%s %s\n%s %s",
		headerLabel.Render("Total:   "), headerValue.Render(util.FormatBytes(totalBytes)),
		rateDownStyle.Render("Download:"), util.FormatBytes(totalIn),
		rateUpStyle.Render("Upload:  "), util.FormatBytes(totalOut),
	)
	card1 := cardStyle.Width(cardWidth).Render(
		headerLabel.Render("DAY VOLUME") + "\n" + volContent,
	)

	// Card 2: Live Rate
	var rateIn, rateOut, totalRate float64
	if m.live != nil {
		rateIn = m.live.TotalRateIn
		rateOut = m.live.TotalRateOut
		totalRate = m.live.TotalRate
	}

	rateContent := fmt.Sprintf(
		"%s %s\n%s %s\n%s %s",
		headerLabel.Render("Current: "), headerValue.Render(util.FormatRate(totalRate)),
		rateDownStyle.Render("Inflow:  "), util.FormatRate(rateIn),
		rateUpStyle.Render("Outflow: "), util.FormatRate(rateOut),
	)
	card2 := cardStyle.Width(cardWidth).Render(
		headerLabel.Render("LIVE SPEED") + "\n" + rateContent,
	)

	// Card 3: Categories & Active Apps
	extPct, lanPct := 0.0, 0.0
	if m.summary != nil && totalBytes > 0 {
		extPct = float64(m.summary.ExternalBytes) / float64(totalBytes) * 100
		lanPct = float64(m.summary.PrivateBytes) / float64(totalBytes) * 100
	}
	activeApps := len(m.apps)

	mixContent := fmt.Sprintf(
		"%s %d apps\n%s %.1f%%\n%s %.1f%%",
		headerLabel.Render("Active:  "), activeApps,
		mutedText.Render("External:"), extPct,
		mutedText.Render("LAN/Priv:"), lanPct,
	)
	card3 := cardStyle.Width(cardWidth).Render(
		headerLabel.Render("CATEGORIES") + "\n" + mixContent,
	)

	return lipgloss.JoinHorizontal(lipgloss.Top, card1, " ", card2, " ", card3)
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

	return fmt.Sprintf("%s   │   %s   │   %s", dateNav, sortIndicator, searchBox)
}

func (m Model) renderTable() string {
	// Table Headers
	colApp := 32
	colCat := 14
	colDown := 13
	colUp := 13
	colTotal := 13
	colRate := 13

	header := fmt.Sprintf(
		"  %-*s %-*s %*s %*s %*s %*s",
		colApp, "APPLICATION",
		colCat, "CATEGORY",
		colDown, "DOWNLOAD",
		colUp, "UPLOAD",
		colTotal, "TOTAL",
		colRate, "RATE",
	)
	headerLine := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#2E2E3E")).
		Render(header)

	var rows []string
	rows = append(rows, headerLine)

	if len(m.apps) == 0 {
		emptyMsg := "  (No network activity recorded for this date / filter)"
		rows = append(rows, mutedText.Render(emptyMsg))
	} else {
		// Available vertical space for table rows
		maxRows := m.height - 13
		if maxRows < 5 {
			maxRows = 5
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
			if len(appName) > colApp-1 {
				appName = appName[:colApp-4] + "..."
			}

			rateStr := "-"
			if app.RateIn+app.RateOut > 0 {
				rateStr = util.FormatRate(app.RateIn + app.RateOut)
			}

			rowStr := fmt.Sprintf(
				"%-*s %-*s %*s %*s %*s %*s",
				colApp, appName,
				colCat, app.Identity.Category,
				colDown, util.FormatBytes(app.BytesIn),
				colUp, util.FormatBytes(app.BytesOut),
				colTotal, util.FormatBytes(app.TotalBytes),
				colRate, rateStr,
			)

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
	return lipgloss.NewStyle().
		Foreground(mutedColor).
		Render(hintStr)
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
