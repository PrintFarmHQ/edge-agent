package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	discoverySourceBambuLAN       = "bambu_lan_ssdp"
	telemetrySourceBambuLAN       = "bambu_lan_discovery"
	bambuLANDiscoveryMulticastIP  = "239.255.255.250"
	bambuLANDiscoveryListenPort   = 2021
	bambuLANDiscoverySearchST     = "urn:bambulab-com:device:3dprinter:1"
	bambuLANDiscoveryCacheTTL     = 2 * time.Minute
	bambuLANProbeHostCacheTTL     = 30 * time.Minute
	bambuLANDiscoveryReadBufSize  = 16 * 1024
	bambuLANDiscoveryProbeSpacing = 200 * time.Millisecond
	bambuLANDiscoveryProbeBursts  = 2
	bambuLANDiscoveryUnicastPort  = 1900
	bambuLANDiscoveryUnicastLimit = 512
	bambuLANDiscoveryBatchSize    = 8
	bambuLANDiscoveryQuietWindow  = 200 * time.Millisecond
)

var bambuLANDiscoveryProbePorts = []int{2021, 1900}

type bambuLANDiscoveryDevice struct {
	PrinterID       string
	Host            string
	Location        string
	Name            string
	Model           string
	ConnectMode     string
	BindState       string
	SecurityLink    string
	FirmwareVersion string
	WiFiSignalDBM   string
	Capability      string
}

type bambuLANDiscoveryResult struct {
	Devices         []bambuLANDiscoveryDevice
	ListenPort      int
	ProbePorts      []int
	PacketsReceived int
	PacketsParsed   int
	UnicastHosts    int
}

type bambuLANDiscoveryRecord struct {
	Snapshot bindingSnapshot
	Host     string
	Location string
	LastSeen time.Time
}

type bambuLANDiscoveryOptions struct {
	PreferredHosts []string
}

var discoverBambuLANPrinters = defaultDiscoverBambuLANPrinters

func (a *agent) executeBambuLANDiscovery(ctx context.Context, probeTimeout time.Duration) ([]discoveryCandidateResult, error) {
	requestTimeout := probeTimeout
	preferredHosts := a.snapshotBambuLANProbeHosts(16)
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.DiscoveryProbeTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.MoonrakerRequestTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = 2500 * time.Millisecond
	}
	minimumTimeout := 15 * time.Second
	if len(preferredHosts) > 0 {
		minimumTimeout = 6 * time.Second
	}
	if requestTimeout < minimumTimeout {
		requestTimeout = minimumTimeout
	}

	discoveryResult, err := discoverBambuLANPrinters(ctx, requestTimeout, bambuLANDiscoveryOptions{
		PreferredHosts: preferredHosts,
	})
	if err != nil {
		return nil, err
	}
	a.audit("bambu_lan_discovery_probe_summary", map[string]any{
		"listen_port":      discoveryResult.ListenPort,
		"probe_ports":      append([]int(nil), discoveryResult.ProbePorts...),
		"packets_received": discoveryResult.PacketsReceived,
		"packets_parsed":   discoveryResult.PacketsParsed,
		"devices_seen":     len(discoveryResult.Devices),
		"unicast_hosts":    discoveryResult.UnicastHosts,
		"timeout_ms":       requestTimeout.Milliseconds(),
	})
	devices := discoveryResult.Devices
	if len(devices) == 0 {
		return nil, nil
	}
	a.recordBambuLANProbeHosts(devices)
	sort.Slice(devices, func(i, j int) bool {
		return strings.TrimSpace(devices[i].PrinterID) < strings.TrimSpace(devices[j].PrinterID)
	})

	now := time.Now().UTC()
	out := make([]discoveryCandidateResult, 0, len(devices))
	records := make([]bambuLANDiscoveryRecord, 0, len(devices))
	for _, device := range devices {
		printerID := strings.TrimSpace(device.PrinterID)
		host := strings.TrimSpace(device.Host)
		if printerID == "" || host == "" {
			continue
		}
		if !isBambuLANDiscoveryEligibleDevice(device) {
			a.audit("bambu_lan_discovery_skipped_device", map[string]any{
				"printer_id":   printerID,
				"host":         host,
				"connect_mode": strings.TrimSpace(device.ConnectMode),
				"bind_state":   strings.TrimSpace(device.BindState),
				"reason":       "unsupported_connect_mode",
				"device_name":  strings.TrimSpace(device.Name),
				"device_model": strings.TrimSpace(device.Model),
			})
			continue
		}
		detectedName := strings.TrimSpace(device.Name)
		if detectedName == "" {
			detectedName = printerID
		}
		snapshot := bindingSnapshot{
			PrinterState:      "idle",
			JobState:          "pending",
			TelemetrySource:   telemetrySourceBambuLAN,
			DetectedName:      detectedName,
			DetectedModelHint: strings.TrimSpace(device.Model),
		}
		evidence := buildBambuLANDiscoveryEvidence(device)
		out = append(out, discoveryCandidateResult{
			AdapterFamily:       "bambu",
			EndpointURL:         formatBambuPrinterEndpoint(printerID),
			Status:              "reachable",
			CurrentPrinterState: snapshot.PrinterState,
			CurrentJobState:     snapshot.JobState,
			DetectedPrinterName: snapshot.DetectedName,
			DetectedModelHint:   snapshot.DetectedModelHint,
			Evidence:            evidence,
		})
		records = append(records, bambuLANDiscoveryRecord{
			Snapshot: snapshot,
			Host:     host,
			Location: strings.TrimSpace(device.Location),
			LastSeen: now,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].EndpointURL) < strings.TrimSpace(out[j].EndpointURL)
	})
	if len(out) == 0 {
		return nil, nil
	}
	a.recordBambuLANDiscoveryRecords(records, out)
	if len(out) > 0 {
		endpoints := make([]string, 0, len(out))
		hosts := make([]string, 0, len(records))
		for idx, candidate := range out {
			endpoints = append(endpoints, strings.TrimSpace(candidate.EndpointURL))
			if idx < len(records) {
				hosts = append(hosts, strings.TrimSpace(records[idx].Host))
			}
		}
		a.audit("bambu_lan_discovery_candidates", map[string]any{
			"count":            len(out),
			"endpoints":        endpoints,
			"hosts":            hosts,
			"listen_port":      discoveryResult.ListenPort,
			"packets_received": discoveryResult.PacketsReceived,
			"packets_parsed":   discoveryResult.PacketsParsed,
			"unicast_hosts":    discoveryResult.UnicastHosts,
		})
	}
	return out, nil
}

func defaultDiscoverBambuLANPrinters(
	ctx context.Context,
	timeout time.Duration,
	options bambuLANDiscoveryOptions,
) (bambuLANDiscoveryResult, error) {
	result := bambuLANDiscoveryResult{
		ProbePorts: append([]int(nil), bambuLANDiscoveryProbePorts...),
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	conn, listenPort, err := openBambuLANDiscoverySocket()
	if err != nil {
		return result, err
	}
	defer conn.Close()
	result.ListenPort = listenPort

	if deadline, ok := ctx.Deadline(); ok {
		if timeoutUntilDeadline := time.Until(deadline); timeoutUntilDeadline > 0 && timeoutUntilDeadline < timeout {
			timeout = timeoutUntilDeadline
		}
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return result, fmt.Errorf("deadline failed: %w", err)
	}
	seen := map[string]struct{}{}
	out := make([]bambuLANDiscoveryDevice, 0, 8)
	if err := sendBambuLANDiscoveryProbes(ctx, conn); err != nil {
		return result, err
	}
	collectBambuLANDiscoveryResponses(conn, deadline, seen, &out, &result, bambuLANDiscoveryQuietWindow)

	unicastHosts := bambuLANDiscoveryUnicastHosts(options.PreferredHosts)
	result.UnicastHosts = len(unicastHosts)
	if err := probeBambuLANDirectHosts(ctx, conn, deadline, unicastHosts, &result, seen, &out); err != nil {
		return result, err
	}

	if !hasEligibleBambuLANDevice(out) && len(out) > 0 {
		focusedHosts := make([]string, 0, len(out))
		for _, device := range out {
			host := strings.TrimSpace(device.Host)
			if host == "" {
				continue
			}
			focusedHosts = append(focusedHosts, host)
		}
		if err := probeBambuLANDirectHosts(ctx, conn, deadline, focusedHosts, &result, seen, &out); err != nil {
			return result, err
		}
	}
	collectBambuLANDiscoveryResponses(conn, deadline, seen, &out, &result, time.Until(deadline))
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].PrinterID) < strings.TrimSpace(out[j].PrinterID)
	})
	result.Devices = out
	return result, nil
}

func probeBambuLANDirectHosts(
	ctx context.Context,
	conn *net.UDPConn,
	deadline time.Time,
	hosts []string,
	result *bambuLANDiscoveryResult,
	seen map[string]struct{},
	out *[]bambuLANDiscoveryDevice,
) error {
	normalizedHosts := normalizeBambuLANDiscoveryHosts(hosts)
	if len(normalizedHosts) == 0 {
		return nil
	}
	rounds := directProbeRoundsForHostCount(len(normalizedHosts))
	for round := 0; round < rounds; round++ {
		for start := 0; start < len(normalizedHosts); start += bambuLANDiscoveryBatchSize {
			if err := ctx.Err(); err != nil {
				return err
			}
			if time.Now().After(deadline) {
				return nil
			}
			end := start + bambuLANDiscoveryBatchSize
			if end > len(normalizedHosts) {
				end = len(normalizedHosts)
			}
			if err := sendBambuLANDirectProbeBatch(conn, normalizedHosts[start:end]); err != nil {
				return err
			}
			collectBambuLANDiscoveryResponses(conn, deadline, seen, out, result, bambuLANDiscoveryQuietWindow)
		}
		if hasEligibleBambuLANDevice(*out) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(bambuLANDiscoveryProbeSpacing):
		}
	}
	return nil
}

func sendBambuLANDirectProbeBatch(conn *net.UDPConn, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}
	payload := buildBambuLANDiscoverySearchPayload(bambuLANDiscoveryUnicastPort)
	successCount := 0
	var sendErrs []string
	for _, host := range hosts {
		if strings.TrimSpace(host) == "" {
			continue
		}
		if _, err := conn.WriteToUDP(payload, &net.UDPAddr{
			IP:   net.ParseIP(strings.TrimSpace(host)),
			Port: bambuLANDiscoveryUnicastPort,
		}); err != nil {
			sendErrs = append(sendErrs, fmt.Sprintf("%s:%d probe failed: %v", strings.TrimSpace(host), bambuLANDiscoveryUnicastPort, err))
			continue
		}
		successCount++
	}
	if successCount == 0 && len(sendErrs) > 0 {
		return errors.New(strings.Join(sendErrs, "; "))
	}
	return nil
}

func collectBambuLANDiscoveryResponses(
	conn *net.UDPConn,
	deadline time.Time,
	seen map[string]struct{},
	out *[]bambuLANDiscoveryDevice,
	result *bambuLANDiscoveryResult,
	quietWindow time.Duration,
) {
	if conn == nil || result == nil || out == nil {
		return
	}
	buffer := make([]byte, bambuLANDiscoveryReadBufSize)
	if quietWindow <= 0 {
		quietWindow = bambuLANDiscoveryQuietWindow
	}
	readDeadline := deadline
	if windowDeadline := time.Now().Add(quietWindow); windowDeadline.Before(readDeadline) {
		readDeadline = windowDeadline
	}
	for {
		if time.Now().After(deadline) {
			return
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return
		}
		n, remoteAddr, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				return
			}
			if errors.Is(readErr, context.DeadlineExceeded) || errors.Is(readErr, context.Canceled) {
				return
			}
			return
		}
		result.PacketsReceived++
		device, ok := parseBambuLANDiscoveryResponse(buffer[:n], remoteAddr)
		if !ok {
			continue
		}
		result.PacketsParsed++
		key := strings.ToLower(strings.TrimSpace(device.PrinterID))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		*out = append(*out, device)
		readDeadline = deadline
		if windowDeadline := time.Now().Add(quietWindow); windowDeadline.Before(readDeadline) {
			readDeadline = windowDeadline
		}
	}
}

func openBambuLANDiscoverySocket() (*net.UDPConn, int, error) {
	listenPorts := []int{bambuLANDiscoveryListenPort, 0}
	var errs []string
	for _, port := range listenPorts {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err == nil {
			return conn, conn.LocalAddr().(*net.UDPAddr).Port, nil
		}
		errs = append(errs, fmt.Sprintf("port %d listen failed: %v", port, err))
	}
	return nil, 0, errors.New(strings.Join(errs, "; "))
}

func sendBambuLANDiscoveryProbes(ctx context.Context, conn *net.UDPConn) error {
	multicastIP := net.ParseIP(bambuLANDiscoveryMulticastIP)
	if multicastIP == nil {
		return errors.New("invalid bambu multicast discovery ip")
	}
	var sendErrs []string
	successCount := 0
	for attempt := 0; attempt < bambuLANDiscoveryProbeBursts; attempt++ {
		for _, port := range bambuLANDiscoveryProbePorts {
			payload := buildBambuLANDiscoverySearchPayload(port)
			if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: multicastIP, Port: port}); err != nil {
				sendErrs = append(sendErrs, fmt.Sprintf("port %d probe failed: %v", port, err))
				continue
			}
			successCount++
		}
		if attempt == bambuLANDiscoveryProbeBursts-1 {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(bambuLANDiscoveryProbeSpacing):
		}
	}
	if successCount == 0 {
		return errors.New(strings.Join(sendErrs, "; "))
	}
	return nil
}

func bambuLANDiscoveryUnicastHosts(preferredHosts []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, bambuLANDiscoveryUnicastLimit)
	appendHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			return
		}
		if _, exists := seen[host]; exists {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}

	for _, host := range preferredHosts {
		if len(out) >= bambuLANDiscoveryUnicastLimit {
			return out
		}
		appendHost(host)
	}
	for _, host := range activePrivateIPv4Hosts() {
		if len(out) >= bambuLANDiscoveryUnicastLimit {
			return out
		}
		appendHost(host)
	}

	if len(out) > 0 {
		return out
	}

	cidrs := localPrivateIPv4CIDRs()
	if len(cidrs) == 0 {
		return nil
	}
	for _, cidr := range cidrs {
		remaining := bambuLANDiscoveryUnicastLimit - len(out)
		if remaining <= 0 {
			break
		}
		for _, host := range enumerateCIDRHosts(cidr, remaining) {
			appendHost(host)
			if len(out) >= bambuLANDiscoveryUnicastLimit {
				break
			}
		}
	}
	return out
}

func buildBambuLANDiscoverySearchPayload(targetPort int) []byte {
	return []byte(strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		fmt.Sprintf("HOST: %s:%d", bambuLANDiscoveryMulticastIP, targetPort),
		`MAN: "ssdp:discover"`,
		"MX: 1",
		"ST: " + bambuLANDiscoverySearchST,
		"",
		"",
	}, "\r\n"))
}

func isBambuLANDiscoveryEligibleDevice(device bambuLANDiscoveryDevice) bool {
	connectMode := strings.ToLower(strings.TrimSpace(device.ConnectMode))
	return connectMode == "" || connectMode == "lan"
}

func hasEligibleBambuLANDevice(devices []bambuLANDiscoveryDevice) bool {
	for _, device := range devices {
		if isBambuLANDiscoveryEligibleDevice(device) {
			return true
		}
	}
	return false
}

func normalizeBambuLANDiscoveryHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			continue
		}
		host = ip.String()
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func directProbeRoundsForHostCount(hostCount int) int {
	switch {
	case hostCount <= 0:
		return 0
	case hostCount <= 4:
		return 6
	case hostCount <= 16:
		return 4
	case hostCount <= 64:
		return 3
	default:
		return 2
	}
}

func buildBambuLANDiscoveryEvidence(device bambuLANDiscoveryDevice) map[string]any {
	evidence := map[string]any{
		"source":           discoverySourceBambuLAN,
		"discovery_source": discoverySourceBambuLAN,
		"ip_address":       strings.TrimSpace(device.Host),
	}
	if location := strings.TrimSpace(device.Location); location != "" {
		evidence["location"] = location
	}
	if connectMode := strings.TrimSpace(device.ConnectMode); connectMode != "" {
		evidence["dev_connect"] = connectMode
		evidence["lan_mode_detected"] = strings.EqualFold(connectMode, "lan")
	}
	if bindState := strings.TrimSpace(device.BindState); bindState != "" {
		evidence["dev_bind"] = bindState
	}
	if securityLink := strings.TrimSpace(device.SecurityLink); securityLink != "" {
		evidence["dev_security_link"] = securityLink
	}
	if firmwareVersion := strings.TrimSpace(device.FirmwareVersion); firmwareVersion != "" {
		evidence["firmware_version"] = firmwareVersion
	}
	if signal := strings.TrimSpace(device.WiFiSignalDBM); signal != "" {
		evidence["wifi_signal_dbm"] = signal
	}
	if capability := strings.TrimSpace(device.Capability); capability != "" {
		evidence["device_capability"] = capability
	}
	return evidence
}

func parseBambuLANDiscoveryResponse(payload []byte, remoteAddr *net.UDPAddr) (bambuLANDiscoveryDevice, bool) {
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	headers := make(map[string]string)
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue
		}
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if key == "" || value == "" {
			continue
		}
		if _, exists := headers[key]; !exists {
			headers[key] = value
		}
	}

	st := strings.ToLower(strings.TrimSpace(firstNonEmpty(headers["st"], headers["nt"])))
	usn := strings.TrimSpace(headers["usn"])
	if st != "" && !strings.Contains(st, bambuLANDiscoverySearchST) && !strings.Contains(strings.ToLower(usn), "bambu") {
		return bambuLANDiscoveryDevice{}, false
	}

	printerID := extractBambuLANDiscoveryPrinterID(headers)
	if printerID == "" {
		return bambuLANDiscoveryDevice{}, false
	}
	host := extractBambuLANDiscoveryHost(headers, remoteAddr)
	if host == "" {
		return bambuLANDiscoveryDevice{}, false
	}

	return bambuLANDiscoveryDevice{
		PrinterID: printerID,
		Host:      host,
		Location:  strings.TrimSpace(headers["location"]),
		Name: strings.TrimSpace(firstNonEmpty(
			headers["devname.bambu.com"],
			headers["dev_name.bambu.com"],
			headers["devname"],
			headers["name"],
		)),
		Model: strings.TrimSpace(firstNonEmpty(
			headers["devmodel.bambu.com"],
			headers["dev_model.bambu.com"],
			headers["model"],
		)),
		ConnectMode:     strings.TrimSpace(headers["devconnect.bambu.com"]),
		BindState:       strings.TrimSpace(headers["devbind.bambu.com"]),
		SecurityLink:    strings.TrimSpace(headers["devseclink.bambu.com"]),
		FirmwareVersion: strings.TrimSpace(headers["devversion.bambu.com"]),
		WiFiSignalDBM:   strings.TrimSpace(headers["devsignal.bambu.com"]),
		Capability:      strings.TrimSpace(headers["devcap.bambu.com"]),
	}, true
}

func extractBambuLANDiscoveryPrinterID(headers map[string]string) string {
	for _, key := range []string{
		"devserialnumber.bambu.com",
		"devsn.bambu.com",
		"x-bbl-serial",
		"serial",
		"dev_id",
		"device-id",
	} {
		if value := strings.TrimSpace(headers[key]); value != "" {
			return value
		}
	}

	usn := strings.TrimSpace(headers["usn"])
	if usn == "" {
		return ""
	}
	primary := usn
	if idx := strings.Index(primary, "::"); idx >= 0 {
		primary = primary[:idx]
	}
	primary = strings.TrimSpace(strings.TrimPrefix(primary, "uuid:"))
	return primary
}

func extractBambuLANDiscoveryHost(headers map[string]string, remoteAddr *net.UDPAddr) string {
	location := strings.TrimSpace(headers["location"])
	if location != "" {
		if ip := net.ParseIP(location); ip != nil {
			return ip.String()
		}
		if parsed, err := url.Parse(location); err == nil {
			if host := strings.TrimSpace(parsed.Hostname()); host != "" {
				return host
			}
		}
	}
	if remoteAddr != nil && remoteAddr.IP != nil {
		return strings.TrimSpace(remoteAddr.IP.String())
	}
	return ""
}

func (a *agent) recordBambuLANDiscoveryRecords(records []bambuLANDiscoveryRecord, candidates []discoveryCandidateResult) {
	if len(records) == 0 || len(candidates) == 0 {
		return
	}
	now := time.Now().UTC()
	recordByPrinterID := make(map[string]bambuLANDiscoveryRecord, len(records))
	for idx, candidate := range candidates {
		if idx >= len(records) {
			break
		}
		printerID, err := parseBambuPrinterEndpointID(candidate.EndpointURL)
		if err != nil {
			continue
		}
		recordByPrinterID[strings.ToLower(strings.TrimSpace(printerID))] = records[idx]
	}
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANRecords == nil {
		a.bambuLANRecords = make(map[string]bambuLANDiscoveryRecord)
	}
	for _, candidate := range candidates {
		printerID, err := parseBambuPrinterEndpointID(candidate.EndpointURL)
		if err != nil {
			continue
		}
		record, ok := recordByPrinterID[strings.ToLower(strings.TrimSpace(printerID))]
		if !ok {
			continue
		}
		record.LastSeen = now
		a.bambuLANRecords[strings.ToLower(strings.TrimSpace(printerID))] = record
	}
	a.pruneBambuLANRecordsLocked(now)
}

func (a *agent) snapshotBambuLANProbeHosts(limit int) []string {
	if limit <= 0 {
		return nil
	}
	now := time.Now().UTC()
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANProbeHosts == nil {
		a.bambuLANProbeHosts = make(map[string]time.Time)
	}
	a.pruneBambuLANProbeHostsLocked(now)
	type hostEntry struct {
		host   string
		seenAt time.Time
	}
	entries := make([]hostEntry, 0, len(a.bambuLANProbeHosts))
	for host, seenAt := range a.bambuLANProbeHosts {
		entries = append(entries, hostEntry{host: host, seenAt: seenAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].seenAt.Equal(entries[j].seenAt) {
			return entries[i].host < entries[j].host
		}
		return entries[i].seenAt.After(entries[j].seenAt)
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]string, 0, len(entries))
	for _, item := range entries {
		out = append(out, item.host)
	}
	return out
}

func (a *agent) recordBambuLANProbeHosts(devices []bambuLANDiscoveryDevice) {
	if len(devices) == 0 {
		return
	}
	now := time.Now().UTC()
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANProbeHosts == nil {
		a.bambuLANProbeHosts = make(map[string]time.Time)
	}
	for _, device := range devices {
		host := strings.TrimSpace(device.Host)
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			continue
		}
		a.bambuLANProbeHosts[ip.String()] = now
	}
	a.pruneBambuLANProbeHostsLocked(now)
}

func (a *agent) pruneBambuLANProbeHostsLocked(now time.Time) {
	if a.bambuLANProbeHosts == nil {
		a.bambuLANProbeHosts = make(map[string]time.Time)
	}
	for host, seenAt := range a.bambuLANProbeHosts {
		if now.Sub(seenAt) > bambuLANProbeHostCacheTTL {
			delete(a.bambuLANProbeHosts, host)
		}
	}
}

func (a *agent) fetchBambuLANSnapshotFromEndpoint(_ context.Context, endpointURL string) (bindingSnapshot, error) {
	printerID, err := parseBambuPrinterEndpointID(endpointURL)
	if err != nil {
		return bindingSnapshot{}, err
	}
	key := strings.ToLower(strings.TrimSpace(printerID))
	if key == "" {
		return bindingSnapshot{}, errors.New("validation_error: missing bambu printer identifier")
	}

	now := time.Now().UTC()
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANRecords == nil {
		a.bambuLANRecords = make(map[string]bambuLANDiscoveryRecord)
	}
	a.pruneBambuLANRecordsLocked(now)
	record, ok := a.bambuLANRecords[key]
	if !ok {
		return bindingSnapshot{}, fmt.Errorf("connection error: bambu lan printer %q has not been discovered on the local network", strings.TrimSpace(printerID))
	}
	return record.Snapshot, nil
}

func (a *agent) pruneBambuLANRecordsLocked(now time.Time) {
	if a.bambuLANRecords == nil {
		a.bambuLANRecords = make(map[string]bambuLANDiscoveryRecord)
	}
	for key, record := range a.bambuLANRecords {
		if now.Sub(record.LastSeen) > bambuLANDiscoveryCacheTTL {
			delete(a.bambuLANRecords, key)
		}
	}
}

func activePrivateIPv4Hosts() []string {
	allowedCIDRs := localPrivateIPv4CIDRs()
	if len(allowedCIDRs) == 0 {
		return nil
	}
	output, err := runARPCommand([]string{"arp", "-an"})
	if err != nil {
		return nil
	}
	return parseActivePrivateIPv4HostsFromARP(string(output), allowedCIDRs)
}

func parseActivePrivateIPv4HostsFromARP(raw string, allowedCIDRs []string) []string {
	if strings.TrimSpace(raw) == "" || len(allowedCIDRs) == 0 {
		return nil
	}
	networks := make([]*net.IPNet, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || network == nil {
			continue
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 32)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), "(incomplete)") {
			continue
		}
		start := strings.Index(line, "(")
		end := strings.Index(line, ")")
		if start < 0 || end <= start+1 {
			continue
		}
		host := strings.TrimSpace(line[start+1 : end])
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			continue
		}
		inAllowedNetwork := false
		for _, network := range networks {
			if network.Contains(ip) {
				inAllowedNetwork = true
				break
			}
		}
		if !inAllowedNetwork {
			continue
		}
		host = ip.String()
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
