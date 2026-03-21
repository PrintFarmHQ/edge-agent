package main

import (
	"strings"
	"testing"
)

func TestBuildStartupBannerIncludesDashboard(t *testing.T) {
	banner := buildStartupBanner(startupBannerInfo{
		DashboardURL:    "http://127.0.0.1:55189/",
		EnabledAdapters: []string{"moonraker", "bambu"},
	}, false)

	if !strings.Contains(banner, "PrintFarmHQ Edge Agent") {
		t.Fatalf("banner missing title: %q", banner)
	}
	if !strings.Contains(banner, "Dashboard http://127.0.0.1:55189/") {
		t.Fatalf("banner missing dashboard url: %q", banner)
	}
	if !strings.Contains(banner, "Adapters  moonraker, bambu") {
		t.Fatalf("banner missing adapters: %q", banner)
	}
	if strings.Contains(banner, "Port") {
		t.Fatalf("banner should not show port: %q", banner)
	}
	if strings.Contains(banner, "Entry") {
		t.Fatalf("banner should not show entry: %q", banner)
	}
	if strings.Contains(banner, "Control") {
		t.Fatalf("banner should not show control: %q", banner)
	}
}

func TestBuildStartupBannerAlertOnlyMode(t *testing.T) {
	banner := buildStartupBanner(startupBannerInfo{
		DashboardURL:  "http://127.0.0.1:55189/",
		ShowAlertOnly: true,
		AlertMessage:  "Paste a valid API key in the dashboard.",
	}, false)

	if strings.Contains(banner, "Adapters") {
		t.Fatalf("alert-only banner should not show adapters: %q", banner)
	}
	if !strings.Contains(banner, "Alert") {
		t.Fatalf("alert-only banner should show alert: %q", banner)
	}
}

func TestVisibleWidthIgnoresANSICodes(t *testing.T) {
	raw := ansiBold + ansiCyan + "PrintFarmHQ" + ansiReset
	if got := visibleWidth(raw); got != len("PrintFarmHQ") {
		t.Fatalf("visibleWidth = %d, want %d", got, len("PrintFarmHQ"))
	}
}
