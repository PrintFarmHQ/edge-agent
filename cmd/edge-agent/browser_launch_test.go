package main

import (
	"testing"
	"time"
)

func TestOpenBrowserForLocalDashboardLaunchesURL(t *testing.T) {
	a := newTestAgent(t)
	original := launchBrowserURL
	originalShould := shouldAutoOpenBrowserFunc
	t.Cleanup(func() {
		launchBrowserURL = original
		shouldAutoOpenBrowserFunc = originalShould
	})

	triggered := make(chan string, 1)
	launchBrowserURL = func(rawURL string) error {
		triggered <- rawURL
		return nil
	}
	shouldAutoOpenBrowserFunc = func() bool { return true }

	a.openBrowserForLocalDashboard("http://127.0.0.1:55189/")

	select {
	case got := <-triggered:
		if got != "http://127.0.0.1:55189/" {
			t.Fatalf("browser url = %q, want http://127.0.0.1:55189/", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("expected browser launch to be triggered")
	}
}
