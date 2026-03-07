package main

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	bambustore "printfarmhq/edge-agent/internal/store"
)

const (
	bambuLANFTPSPort            = "990"
	bambuLANFTPSUsername        = bambuLANMQTTUsername
	bambuLANProjectFileTimeout  = 5 * time.Second
	bambuLANProjectFileJobType  = 1
	bambuLANProjectFilePlateIdx = 0
)

var bambuLANPASVPattern = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

var uploadBambuLANArtifact = defaultUploadBambuLANArtifact
var dispatchBambuLANProjectFile = defaultDispatchBambuLANProjectFile

type bambuLANProjectFileRequest struct {
	RemoteName  string
	FileMD5     string
	ProjectPath string
}

func (a *agent) executeBambuLANPrintAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}

	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		if isBambuLANCredentialsUnavailable(err) {
			return a.decorateBambuLANCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}

	localPath, remoteName, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	defer a.cleanupArtifact(localPath)

	if !strings.EqualFold(filepath.Ext(strings.TrimSpace(remoteName)), ".3mf") {
		return fmt.Errorf(
			"validation_error: bambu lan print start requires a .3mf artifact, got %q",
			strings.TrimSpace(remoteName),
		)
	}

	fileBytes, err := osReadFile(localPath)
	if err != nil {
		return err
	}
	fileMD5Sum := md5.Sum(fileBytes)
	fileMD5 := strings.ToUpper(hex.EncodeToString(fileMD5Sum[:]))
	remoteStartFileName := normalizeBambuLANRemoteStartFilename(remoteName)
	projectPath := defaultBambuLANProjectFileParam()

	a.audit("artifact_downloaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})
	a.audit("bambu_lan_upload_attempt", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       remoteStartFileName,
		"transport":      "bambu_lan_ftps",
		"adapter_family": "bambu",
	})

	if err := uploadBambuLANArtifact(ctx, credentials, remoteStartFileName, fileBytes); err != nil {
		a.audit("bambu_lan_upload_failed", map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"filename":       remoteStartFileName,
			"transport":      "bambu_lan_ftps",
			"adapter_family": "bambu",
			"error":          err.Error(),
		})
		return fmt.Errorf("bambu_lan_upload_failed: %w", err)
	}

	a.audit("bambu_lan_upload_success", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       remoteStartFileName,
		"transport":      "bambu_lan_ftps",
		"adapter_family": "bambu",
	})
	a.audit("artifact_uploaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteStartFileName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
		"transport":       "bambu_lan_ftps",
	})

	projectReq := bambuLANProjectFileRequest{
		RemoteName:  remoteStartFileName,
		FileMD5:     fileMD5,
		ProjectPath: projectPath,
	}
	a.audit("bambu_print_start_dispatch_attempt", map[string]any{
		"printer_id":         queuedAction.PrinterID,
		"job_id":             queuedAction.Target.JobID,
		"plate_id":           queuedAction.Target.PlateID,
		"filename":           remoteStartFileName,
		"project_path":       projectPath,
		"transport":          "bambu_lan_mqtt",
		"adapter_family":     "bambu",
		"has_file_md5":       projectReq.FileMD5 != "",
		"uses_fixed_options": true,
	})
	previousEchoAudit := auditBambuLANProjectFileEcho
	auditBambuLANProjectFileEcho = func(payload map[string]any) {
		merged := map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"filename":       remoteStartFileName,
			"project_path":   projectPath,
			"transport":      "bambu_lan_mqtt",
			"adapter_family": "bambu",
		}
		for key, value := range payload {
			merged[key] = value
		}
		a.audit("bambu_print_start_dispatch_echo", merged)
	}
	defer func() {
		auditBambuLANProjectFileEcho = previousEchoAudit
	}()
	if err := dispatchBambuLANProjectFile(ctx, credentials, projectReq); err != nil {
		a.audit("bambu_print_start_dispatch_failure", map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"filename":       remoteStartFileName,
			"project_path":   projectPath,
			"transport":      "bambu_lan_mqtt",
			"adapter_family": "bambu",
			"error":          err.Error(),
		})
		return err
	}

	// Project a queued runtime state immediately so SaaS treats calibration/preparation
	// as an in-progress start instead of an overdue start that never began.
	a.markPrintStartInProgress(queuedAction)

	if err := a.verifyBambuPrintStart(ctx, strings.TrimSpace(printerID)); err != nil {
		return fmt.Errorf("bambu_start_verification_timeout: %w", err)
	}

	a.audit("bambu_print_start_verified", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       remoteStartFileName,
		"project_path":   projectPath,
		"transport":      "bambu_lan_mqtt",
		"adapter_family": "bambu",
	})
	a.audit("print_start_requested", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteStartFileName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
		"transport":       "bambu_lan_mqtt",
	})
	return nil
}

var osReadFile = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func buildBambuLANProjectFilePayload(req bambuLANProjectFileRequest) map[string]any {
	now := time.Now()
	jobID := now.Unix()
	remoteName := strings.TrimSpace(req.RemoteName)
	projectPath := strings.TrimSpace(req.ProjectPath)
	if projectPath == "" {
		projectPath = defaultBambuLANProjectFileParam()
	}
	return map[string]any{
		"sequence_id":    strconv.FormatInt(now.UnixMilli(), 10),
		"command":        "project_file",
		"plate_idx":      bambuLANProjectFilePlateIdx,
		"job_type":       bambuLANProjectFileJobType,
		"job_id":         jobID,
		"project_id":     "0",
		"profile_id":     "0",
		"task_id":        "0",
		"subtask_id":     "0",
		"md5":            strings.ToUpper(strings.TrimSpace(req.FileMD5)),
		"param":          projectPath,
		"url":            fmt.Sprintf("ftp:///%s", remoteName),
		"file":           "",
		"subtask_name":   remoteName,
		"timelapse":      false,
		"bed_leveling":   true,
		"bed_levelling":  true,
		"flow_cali":      false,
		"vibration_cali": false,
		"layer_inspect":  true,
		"use_ams":        false,
		"ams_mapping":    "",
	}
}

func normalizeBambuLANRemoteStartFilename(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	lowered := strings.ToLower(trimmed)
	if strings.HasSuffix(lowered, ".gcode.3mf") {
		return trimmed
	}
	if strings.HasSuffix(lowered, ".3mf") {
		base := strings.TrimSuffix(trimmed, filepath.Ext(trimmed))
		return base + ".gcode.3mf"
	}
	return trimmed + ".gcode.3mf"
}

func defaultBambuLANProjectFileParam() string {
	return "Metadata/plate_1.gcode"
}

func defaultDispatchBambuLANProjectFile(
	ctx context.Context,
	credentials bambustore.BambuLANCredentials,
	req bambuLANProjectFileRequest,
) error {
	host := strings.TrimSpace(credentials.Host)
	serial := strings.TrimSpace(credentials.Serial)
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if host == "" || serial == "" || accessCode == "" {
		return errors.New("validation_error: bambu lan project_file dispatch requires host, serial, and access code")
	}

	brokerAddr := net.JoinHostPort(host, bambuLANMQTTBrokerPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", brokerAddr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("connection error: bambu lan mqtt connection failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	if err := writeMQTTConnect(conn, bambuLANMQTTUsername, accessCode); err != nil {
		return err
	}
	if err := readMQTTConnAck(conn); err != nil {
		return err
	}

	reportTopic := formatBambuLANMQTTReportTopic(serial)
	if err := writeMQTTSubscribe(conn, reportTopic, 1); err != nil {
		return err
	}
	if err := readMQTTSubAck(conn, 1); err != nil {
		return err
	}

	projectPayload := buildBambuLANProjectFilePayload(req)
	sequenceID := strings.TrimSpace(fmt.Sprint(projectPayload["sequence_id"]))
	wirePayload, err := json.Marshal(map[string]any{"print": projectPayload})
	if err != nil {
		return fmt.Errorf("marshal bambu lan project_file payload: %w", err)
	}
	if err := writeMQTTPublish(conn, formatBambuLANMQTTRequestTopic(serial), wirePayload); err != nil {
		return err
	}

	echoCtx, cancel := context.WithTimeout(ctx, bambuLANProjectFileTimeout)
	defer cancel()
	if err := conn.SetReadDeadline(time.Now().Add(bambuLANProjectFileTimeout)); err != nil {
		return err
	}
	for {
		select {
		case <-echoCtx.Done():
			return nil
		default:
		}
		header, packet, err := readMQTTPacket(conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("bambu_start_rejected: bambu lan project_file echo read failed: %w", err)
		}
		publish, err := decodeMQTTPublishPacket(header, packet)
		if err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(publish.Topic), reportTopic) {
			continue
		}

		var payload struct {
			Print map[string]any `json:"print"`
		}
		if err := json.Unmarshal(publish.Payload, &payload); err != nil {
			continue
		}
		if len(payload.Print) == 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(bambuLANValueAsString(payload.Print["command"])), "project_file") {
			continue
		}
		if strings.TrimSpace(bambuLANValueAsString(payload.Print["sequence_id"])) != sequenceID {
			continue
		}

		errCode, hasErrCode := bambuLANValueAsFloat(payload.Print["err_code"])
		echoEvent := map[string]any{
			"sequence_id": sequenceID,
			"result":      strings.TrimSpace(bambuLANValueAsString(payload.Print["result"])),
			"reason":      strings.TrimSpace(bambuLANValueAsString(payload.Print["reason"])),
		}
		if hasErrCode {
			echoEvent["err_code"] = int(errCode)
		}
		auditBambuLANProjectFileEcho(echoEvent)
		if hasErrCode && errCode > 0 {
			return fmt.Errorf(
				"bambu_start_rejected: local project_file rejected err_code=%d result=%s reason=%s",
				int(errCode),
				strings.TrimSpace(bambuLANValueAsString(payload.Print["result"])),
				strings.TrimSpace(bambuLANValueAsString(payload.Print["reason"])),
			)
		}
		if strings.EqualFold(strings.TrimSpace(bambuLANValueAsString(payload.Print["result"])), "failed") {
			return fmt.Errorf(
				"bambu_start_rejected: local project_file returned failed reason=%s",
				strings.TrimSpace(bambuLANValueAsString(payload.Print["reason"])),
			)
		}
		return nil
	}
}

var auditBambuLANProjectFileEcho = func(payload map[string]any) {}

func defaultUploadBambuLANArtifact(
	ctx context.Context,
	credentials bambustore.BambuLANCredentials,
	remoteName string,
	fileBytes []byte,
) error {
	host := strings.TrimSpace(credentials.Host)
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if host == "" || accessCode == "" {
		return errors.New("validation_error: bambu lan upload requires host and access code")
	}
	trimmedRemoteName := strings.TrimSpace(remoteName)
	if trimmedRemoteName == "" {
		return errors.New("validation_error: bambu lan upload requires remote filename")
	}

	client, err := dialBambuLANFTPS(ctx, host)
	if err != nil {
		return err
	}
	defer client.close()

	if err := client.login(bambuLANFTPSUsername, accessCode); err != nil {
		return err
	}
	if err := client.setBinaryMode(); err != nil {
		return err
	}
	if err := client.store(trimmedRemoteName, fileBytes); err != nil {
		return err
	}
	_ = client.quit()
	return nil
}

type bambuLANFTPSClient struct {
	host string
	conn net.Conn
	text *textproto.Conn
}

func dialBambuLANFTPS(ctx context.Context, host string) (*bambuLANFTPSClient, error) {
	trimmedHost := strings.TrimSpace(host)
	if trimmedHost == "" {
		return nil, errors.New("validation_error: missing bambu lan host")
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(trimmedHost, bambuLANFTPSPort), &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         trimmedHost,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connection error: bambu lan ftps connection failed: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client := &bambuLANFTPSClient{
		host: trimmedHost,
		conn: conn,
		text: textproto.NewConn(conn),
	}
	if _, _, err := client.text.ReadResponse(220); err != nil {
		_ = client.close()
		return nil, fmt.Errorf("bambu ftps welcome failed: %w", err)
	}
	return client, nil
}

func (c *bambuLANFTPSClient) login(username, password string) error {
	code, _, err := c.expectAny([]int{230, 331}, "USER %s", strings.TrimSpace(username))
	if err != nil {
		if code == 230 {
			return nil
		}
		return err
	}
	if code == 230 {
		return nil
	}
	if _, _, err := c.command(230, "PASS %s", strings.TrimSpace(password)); err != nil {
		return fmt.Errorf("bambu ftps auth rejected: %w", err)
	}
	_, _, _ = c.command(200, "PBSZ 0")
	_, _, _ = c.command(200, "PROT P")
	return nil
}

func (c *bambuLANFTPSClient) setBinaryMode() error {
	if _, _, err := c.command(200, "TYPE I"); err != nil {
		return err
	}
	return nil
}

func (c *bambuLANFTPSClient) store(remoteName string, fileBytes []byte) error {
	dataAddr, err := c.pasvAddr()
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	dataConn, err := tls.DialWithDialer(dialer, "tcp", dataAddr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("connection error: bambu lan ftps data connection failed: %w", err)
	}
	defer dataConn.Close()

	if _, _, err := c.expectAny([]int{125, 150}, "STOR %s", strings.TrimSpace(remoteName)); err != nil {
		return err
	}
	if _, err := dataConn.Write(fileBytes); err != nil {
		return fmt.Errorf("bambu lan ftps upload failed: %w", err)
	}
	if err := dataConn.Close(); err != nil {
		return fmt.Errorf("bambu lan ftps upload close failed: %w", err)
	}
	if _, _, err := c.readAnyResponse([]int{226, 250}); err != nil {
		return err
	}
	return nil
}

func (c *bambuLANFTPSClient) pasvAddr() (string, error) {
	_, message, err := c.command(227, "PASV")
	if err != nil {
		return "", err
	}
	match := bambuLANPASVPattern.FindStringSubmatch(message)
	if len(match) != 7 {
		return "", fmt.Errorf("bambu lan ftps PASV response malformed: %s", strings.TrimSpace(message))
	}
	host := fmt.Sprintf("%s.%s.%s.%s", match[1], match[2], match[3], match[4])
	p1, err := strconv.Atoi(match[5])
	if err != nil {
		return "", fmt.Errorf("bambu lan ftps PASV port malformed: %w", err)
	}
	p2, err := strconv.Atoi(match[6])
	if err != nil {
		return "", fmt.Errorf("bambu lan ftps PASV port malformed: %w", err)
	}
	port := p1*256 + p2
	if port <= 0 {
		return "", fmt.Errorf("bambu lan ftps PASV port invalid: %d", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (c *bambuLANFTPSClient) quit() error {
	_, _, err := c.command(221, "QUIT")
	return err
}

func (c *bambuLANFTPSClient) close() error {
	if c == nil {
		return nil
	}
	if c.text != nil {
		_ = c.text.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *bambuLANFTPSClient) command(expectCode int, format string, args ...any) (int, string, error) {
	return c.expectAny([]int{expectCode}, format, args...)
}

func (c *bambuLANFTPSClient) expectAny(expectCodes []int, format string, args ...any) (int, string, error) {
	if c == nil || c.text == nil {
		return 0, "", errors.New("bambu ftps client not connected")
	}
	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return 0, "", fmt.Errorf("bambu ftps command failed: %w", err)
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)

	line, err := c.text.ReadLine()
	if err != nil {
		return 0, "", fmt.Errorf("bambu ftps read failed: %w", err)
	}
	if len(line) < 3 {
		return 0, "", fmt.Errorf("bambu ftps response malformed: %s", strings.TrimSpace(line))
	}
	code, convErr := strconv.Atoi(line[:3])
	if convErr != nil {
		return 0, "", fmt.Errorf("bambu ftps response malformed: %s", strings.TrimSpace(line))
	}
	message := line
	if len(line) > 3 && line[3] == '-' {
		for {
			nextLine, readErr := c.text.ReadLine()
			if readErr != nil {
				return code, message, fmt.Errorf("bambu ftps multiline read failed: %w", readErr)
			}
			message += "\n" + nextLine
			if strings.HasPrefix(nextLine, fmt.Sprintf("%03d ", code)) {
				break
			}
		}
	}

	for _, expected := range expectCodes {
		if code == expected {
			return code, message, nil
		}
	}
	return code, message, fmt.Errorf("bambu ftps command %q returned %d: %s", format, code, strings.TrimSpace(message))
}

func (c *bambuLANFTPSClient) readAnyResponse(expectCodes []int) (int, string, error) {
	if c == nil || c.text == nil {
		return 0, "", errors.New("bambu ftps client not connected")
	}
	line, err := c.text.ReadLine()
	if err != nil {
		return 0, "", fmt.Errorf("bambu ftps read failed: %w", err)
	}
	if len(line) < 3 {
		return 0, "", fmt.Errorf("bambu ftps response malformed: %s", strings.TrimSpace(line))
	}
	code, convErr := strconv.Atoi(line[:3])
	if convErr != nil {
		return 0, "", fmt.Errorf("bambu ftps response malformed: %s", strings.TrimSpace(line))
	}
	message := line
	if len(line) > 3 && line[3] == '-' {
		for {
			nextLine, readErr := c.text.ReadLine()
			if readErr != nil {
				return code, message, fmt.Errorf("bambu ftps multiline read failed: %w", readErr)
			}
			message += "\n" + nextLine
			if strings.HasPrefix(nextLine, fmt.Sprintf("%03d ", code)) {
				break
			}
		}
	}

	for _, expected := range expectCodes {
		if code == expected {
			return code, message, nil
		}
	}
	return code, message, fmt.Errorf("bambu ftps response returned %d: %s", code, strings.TrimSpace(message))
}
