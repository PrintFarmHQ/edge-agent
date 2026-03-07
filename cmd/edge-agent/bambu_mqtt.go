package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type defaultBambuPrintCommandPublisher struct{}

func (defaultBambuPrintCommandPublisher) PublishPrintCommand(ctx context.Context, req bambuMQTTCommandRequest) error {
	brokerAddr := strings.TrimSpace(req.BrokerAddr)
	if brokerAddr == "" {
		return errors.New("validation_error: missing bambu mqtt broker address")
	}
	topic := strings.TrimSpace(req.Topic)
	if topic == "" {
		return errors.New("validation_error: missing bambu mqtt topic")
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		return errors.New("validation_error: missing bambu mqtt username")
	}
	password := strings.TrimSpace(req.Password)
	if password == "" {
		return errors.New("validation_error: missing bambu mqtt password")
	}
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return errors.New("validation_error: missing bambu mqtt command")
	}

	host, _, err := net.SplitHostPort(brokerAddr)
	if err != nil {
		return fmt.Errorf("validation_error: invalid bambu mqtt broker address %q: %w", brokerAddr, err)
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", brokerAddr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         strings.TrimSpace(host),
		InsecureSkipVerify: req.InsecureSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("bambu mqtt connection failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	if err := writeMQTTConnect(conn, username, password); err != nil {
		return err
	}
	if err := readMQTTConnAck(conn); err != nil {
		return err
	}

	payload, err := buildBambuMQTTPayload(command, req.Param)
	if err != nil {
		return err
	}
	if err := writeMQTTPublish(conn, topic, payload); err != nil {
		return err
	}
	_, _ = conn.Write([]byte{0xE0, 0x00})
	return nil
}

func buildBambuMQTTPayload(command string, param map[string]any) ([]byte, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, errors.New("validation_error: missing bambu mqtt command")
	}
	printPayload := map[string]any{
		"command":     trimmed,
		"sequence_id": strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	if len(param) > 0 {
		cleanParam := make(map[string]any, len(param))
		for key, value := range param {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			cleanParam[trimmedKey] = value
		}
		if len(cleanParam) > 0 {
			printPayload["param"] = cleanParam
		}
	}
	payload := map[string]any{
		"print": printPayload,
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal bambu mqtt payload: %w", err)
	}
	return out, nil
}

func writeMQTTConnect(conn net.Conn, username, password string) error {
	var variable bytes.Buffer
	variable.Write([]byte{0x00, 0x04})
	variable.WriteString("MQTT")
	variable.WriteByte(0x04) // protocol level 3.1.1
	variable.WriteByte(0xC2) // clean session + username + password
	variable.Write([]byte{0x00, 0x1E})

	clientID := randomKey("pfh-bambu")
	var payload bytes.Buffer
	payload.Write(encodeMQTTUTF8(clientID))
	payload.Write(encodeMQTTUTF8(username))
	payload.Write(encodeMQTTUTF8(password))

	remaining := variable.Len() + payload.Len()
	packet := []byte{0x10}
	packet = append(packet, encodeMQTTRemainingLength(remaining)...)
	packet = append(packet, variable.Bytes()...)
	packet = append(packet, payload.Bytes()...)

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("bambu mqtt connect write failed: %w", err)
	}
	return nil
}

func readMQTTConnAck(conn net.Conn) error {
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("bambu mqtt connack read failed: %w", err)
	}
	if header[0] != 0x20 {
		return fmt.Errorf("bambu mqtt connack invalid header 0x%x", header[0])
	}
	remaining, err := readMQTTRemainingLength(conn)
	if err != nil {
		return fmt.Errorf("bambu mqtt connack read length failed: %w", err)
	}
	if remaining <= 0 {
		return errors.New("bambu mqtt connack missing payload")
	}
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return fmt.Errorf("bambu mqtt connack payload read failed: %w", err)
	}
	if len(payload) < 2 {
		return fmt.Errorf("bambu mqtt connack payload too short: %d", len(payload))
	}
	if payload[1] != 0x00 {
		return fmt.Errorf("bambu mqtt broker rejected connection return_code=%d", payload[1])
	}
	return nil
}

func writeMQTTPublish(conn net.Conn, topic string, payload []byte) error {
	trimmedTopic := strings.TrimSpace(topic)
	if trimmedTopic == "" {
		return errors.New("validation_error: missing mqtt topic")
	}
	var body bytes.Buffer
	body.Write(encodeMQTTUTF8(trimmedTopic))
	body.Write(payload)

	packet := []byte{0x30}
	packet = append(packet, encodeMQTTRemainingLength(body.Len())...)
	packet = append(packet, body.Bytes()...)

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("bambu mqtt publish failed: %w", err)
	}
	return nil
}

func writeMQTTSubscribe(conn net.Conn, topic string, packetID uint16) error {
	trimmedTopic := strings.TrimSpace(topic)
	if trimmedTopic == "" {
		return errors.New("validation_error: missing mqtt topic")
	}
	var body bytes.Buffer
	body.WriteByte(byte(packetID >> 8))
	body.WriteByte(byte(packetID))
	body.Write(encodeMQTTUTF8(trimmedTopic))
	body.WriteByte(0x00)

	packet := []byte{0x82}
	packet = append(packet, encodeMQTTRemainingLength(body.Len())...)
	packet = append(packet, body.Bytes()...)

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("bambu mqtt subscribe failed: %w", err)
	}
	return nil
}

func readMQTTSubAck(conn net.Conn, packetID uint16) error {
	header, payload, err := readMQTTPacket(conn)
	if err != nil {
		return fmt.Errorf("bambu mqtt suback read failed: %w", err)
	}
	if header != 0x90 {
		return fmt.Errorf("bambu mqtt suback invalid header 0x%x", header)
	}
	if len(payload) < 3 {
		return fmt.Errorf("bambu mqtt suback payload too short: %d", len(payload))
	}
	gotPacketID := uint16(payload[0])<<8 | uint16(payload[1])
	if gotPacketID != packetID {
		return fmt.Errorf("bambu mqtt suback packet id = %d, want %d", gotPacketID, packetID)
	}
	if payload[2] == 0x80 {
		return errors.New("bambu mqtt broker rejected subscription")
	}
	return nil
}

func readMQTTPacket(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	remaining, err := readMQTTRemainingLength(conn)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, remaining)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

type mqttPublishPacket struct {
	Topic   string
	Payload []byte
}

func decodeMQTTPublishPacket(header byte, packet []byte) (mqttPublishPacket, error) {
	if header>>4 != 0x03 {
		return mqttPublishPacket{}, fmt.Errorf("not a publish packet: 0x%x", header)
	}
	if len(packet) < 2 {
		return mqttPublishPacket{}, errors.New("mqtt publish packet too short")
	}
	topicLength := int(packet[0])<<8 | int(packet[1])
	if len(packet) < 2+topicLength {
		return mqttPublishPacket{}, errors.New("mqtt publish packet missing topic")
	}
	topic := string(packet[2 : 2+topicLength])
	offset := 2 + topicLength
	qos := (header >> 1) & 0x03
	if qos > 0 {
		if len(packet) < offset+2 {
			return mqttPublishPacket{}, errors.New("mqtt publish packet missing packet identifier")
		}
		offset += 2
	}
	if len(packet) < offset {
		return mqttPublishPacket{}, errors.New("mqtt publish packet invalid payload offset")
	}
	return mqttPublishPacket{
		Topic:   topic,
		Payload: append([]byte(nil), packet[offset:]...),
	}, nil
}

func encodeMQTTUTF8(value string) []byte {
	raw := []byte(value)
	out := make([]byte, 2+len(raw))
	out[0] = byte(len(raw) >> 8)
	out[1] = byte(len(raw))
	copy(out[2:], raw)
	return out
}

func encodeMQTTRemainingLength(value int) []byte {
	if value < 0 {
		value = 0
	}
	out := make([]byte, 0, 4)
	for {
		encoded := byte(value % 128)
		value /= 128
		if value > 0 {
			encoded |= 0x80
		}
		out = append(out, encoded)
		if value == 0 {
			break
		}
	}
	return out
}

func readMQTTRemainingLength(reader io.Reader) (int, error) {
	multiplier := 1
	value := 0
	for i := 0; i < 4; i++ {
		buf := make([]byte, 1)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return 0, err
		}
		encoded := int(buf[0])
		value += (encoded & 127) * multiplier
		if encoded&128 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
	return 0, errors.New("mqtt remaining length exceeds 4 bytes")
}
