package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Brand Colors
	primaryColor   = lipgloss.Color("#7D56F4") // Monito Purple
	secondaryColor = lipgloss.Color("#04B575") // Active Green
	accentColor    = lipgloss.Color("#36F4D4") // Cyan
	warningColor   = lipgloss.Color("#FFAF00") // Amber
	errorColor     = lipgloss.Color("#FF5F87") // Coral Red
	mutedColor     = lipgloss.Color("#626262") // Slate Muted
	subtleColor    = lipgloss.Color("#383838") // Darker Slate
	bgColor        = lipgloss.Color("#1A1A24") // Deep Dark Background

	// Styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Padding(0, 1)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtleColor).
			Padding(0, 1)

	activeCardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(0, 1)

	headerLabel = lipgloss.NewStyle().
			Bold(true).
			Foreground(accentColor)

	headerValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	mutedText = lipgloss.NewStyle().
			Foreground(mutedColor)

	rateUpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF875F"))

	rateDownStyle = lipgloss.NewStyle().
			Foreground(secondaryColor)

	helpKeyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accentColor)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	modalBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2)

	disconnectedBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(errorColor).
			Padding(1, 3)
)
