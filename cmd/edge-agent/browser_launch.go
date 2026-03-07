package main

import (
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var launchBrowserURL = defaultLaunchBrowserURL
var shouldAutoOpenBrowserFunc = shouldAutoOpenBrowser

func (a *agent) openBrowserForLocalDashboard(rawURL string) {
	if a == nil || strings.TrimSpace(rawURL) == "" {
		return
	}
	if !shouldAutoOpenBrowserFunc() {
		return
	}
	go func() {
		time.Sleep(250 * time.Millisecond)
		if err := launchBrowserURL(strings.TrimSpace(rawURL)); err != nil {
			log.Printf("warning: failed to open local dashboard automatically: %v", err)
		}
	}()
}

func shouldAutoOpenBrowser() bool {
	if strings.TrimSpace(os.Getenv("EDGE_AGENT_DISABLE_BROWSER_OPEN")) != "" {
		return false
	}
	return terminalSupportsColor(os.Stdout)
}

func defaultLaunchBrowserURL(rawURL string) error {
	url := strings.TrimSpace(rawURL)
	if url == "" {
		return nil
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
