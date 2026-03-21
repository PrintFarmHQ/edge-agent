package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

type startupBannerInfo struct {
	DashboardURL    string
	EnabledAdapters []string
	ShowAlertOnly   bool
	AlertMessage    string
}

func printStartupBanner(info startupBannerInfo) {
	writer := os.Stdout
	if writer == nil {
		return
	}
	_, _ = io.WriteString(writer, buildStartupBanner(info, terminalSupportsColor(writer)))
}

func buildStartupBanner(info startupBannerInfo, colorize bool) string {
	color := func(code string, raw string) string {
		if !colorize || strings.TrimSpace(raw) == "" {
			return raw
		}
		return code + raw + ansiReset
	}

	title := "PrintFarmHQ Edge Agent"
	if colorize {
		title = ansiBold + ansiCyan + title + ansiReset
	}

	dashboardURL := firstNonEmpty(strings.TrimSpace(info.DashboardURL), "unavailable")
	adapters := strings.Join(info.EnabledAdapters, ", ")
	if strings.TrimSpace(adapters) == "" {
		adapters = "none"
	}

	lines := []string{title}
	if info.ShowAlertOnly {
		lines = append(lines,
			fmt.Sprintf("%s %s", color(ansiGreen, "Dashboard"), dashboardURL),
			fmt.Sprintf("%s %s", color(ansiYellow, "Alert    "), firstNonEmpty(strings.TrimSpace(info.AlertMessage), "Paste a valid API key in the dashboard.")),
		)
	} else {
		lines = append(lines,
			fmt.Sprintf("%s %s", color(ansiGreen, "Dashboard"), dashboardURL),
			fmt.Sprintf("%s %s", color(ansiCyan, "Adapters "), adapters),
		)
	}

	maxWidth := 0
	for _, line := range lines {
		width := visibleWidth(line)
		if width > maxWidth {
			maxWidth = width
		}
	}
	if maxWidth < 32 {
		maxWidth = 32
	}

	var out strings.Builder
	border := "+" + strings.Repeat("-", maxWidth+2) + "+\n"
	out.WriteString("\n")
	out.WriteString(border)
	for _, line := range lines {
		padding := maxWidth - visibleWidth(line)
		out.WriteString("| ")
		out.WriteString(line)
		out.WriteString(strings.Repeat(" ", padding))
		out.WriteString(" |\n")
	}
	out.WriteString(border)
	out.WriteString("\n")
	return out.String()
}

func terminalSupportsColor(file *os.File) bool {
	if file == nil {
		return false
	}
	stat, err := file.Stat()
	if err != nil {
		return false
	}
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return false
	}
	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	if term == "" || term == "dumb" {
		return false
	}
	return true
}

func visibleWidth(raw string) int {
	width := 0
	inEscape := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		switch {
		case inEscape && ch == 'm':
			inEscape = false
		case inEscape:
			continue
		case ch == '\033':
			inEscape = true
		default:
			width++
		}
	}
	return width
}
