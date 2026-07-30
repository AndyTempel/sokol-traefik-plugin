package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	webSocketSoakFrames = 50
	webSocketSoakDelay  = 20 * time.Millisecond
)

const testTokenPath = "/run/secrets/sokol-plugin-token"

type evaluationRequest struct {
	RequestID     string `json:"request_id"`
	Path          string `json:"path"`
	ProtocolType  string `json:"protocol_type"`
	HTTPVersion   string `json:"http_version"`
	Body          []byte `json:"body"`
	BodyTruncated bool   `json:"body_truncated"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: sokol-traefik-harness agent|upstream|check|outage")
	}
	switch os.Args[1] {
	case "agent":
		runAgent()
	case "upstream":
		runUpstream()
	case "check":
		if err := runChecks(false); err != nil {
			log.Fatal(err)
		}
	case "outage":
		if err := runChecks(true); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("unknown harness role")
	}
}

func runAgent() {
	tokenBytes, err := os.ReadFile(testTokenPath)
	if err != nil {
		log.Fatal(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/evaluate" ||
			request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input evaluationRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, 2<<20))
		if err := decoder.Decode(&input); err != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		if input.Path == "/agent-timeout" {
			time.Sleep(500 * time.Millisecond)
		}
		if input.Path == "/agent-malformed" {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"malformed":true}`))
			return
		}
		decision := "allow"
		status := http.StatusOK
		reason := "request_allowed"
		if input.Path == "/blocked" {
			decision = "block"
			status = http.StatusForbidden
			reason = "request_blocked"
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"decision": decision, "status": status, "request_id": input.RequestID,
			"public_reason": reason, "cache_ttl_ms": 0,
		})
	})
	server := &http.Server{
		Addr: ":8082", Handler: handler,
		ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func runUpstream() {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/sse":
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = writer.Write([]byte("data: first\n\n"))
			writer.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			_, _ = writer.Write([]byte("data: second\n\n"))
		case "/chunked":
			_, _ = writer.Write([]byte("first\n"))
			writer.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			_, _ = writer.Write([]byte("second\n"))
		case "/large-download":
			_, _ = writer.Write(bytes.Repeat([]byte("d"), 2<<20))
		case "/uploads/archive", "/chunked-request":
			count, _ := io.Copy(io.Discard, request.Body)
			_, _ = fmt.Fprintf(writer, "%d", count)
		case "/ws", "/api/websocket":
			websocketEcho(writer, request)
		default:
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{
				"status": "upstream", "method": request.Method,
			})
		}
	})
	server := &http.Server{
		Addr: ":8081", Handler: handler,
		ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func runChecks(outage bool) error {
	client := &http.Client{Timeout: 3 * time.Second}
	if err := waitReady(client); err != nil {
		return err
	}
	if outage {
		return expectStatus(client, http.MethodGet, "/", nil, http.StatusOK, "")
	}
	for _, test := range []struct {
		method, path, accept string
		status               int
		contains             string
	}{
		{method: http.MethodGet, path: "/", status: 200, contains: "upstream"},
		{method: http.MethodGet, path: "/blocked", status: 403, contains: "Not on the list."},
		{method: http.MethodGet, path: "/blocked", accept: "application/json", status: 403, contains: "request_blocked"},
		{method: http.MethodGet, path: "/agent-timeout", status: 200, contains: "upstream"},
		{method: http.MethodGet, path: "/agent-malformed", status: 200, contains: "upstream"},
		{method: "PROPFIND", path: "/dav", status: 200, contains: "PROPFIND"},
	} {
		if err := expectStatus(client, test.method, test.path, nil, test.status, test.contains, test.accept); err != nil {
			return err
		}
	}
	if err := checkStreaming(client, "/sse", "data: first"); err != nil {
		return err
	}
	if err := checkStreaming(client, "/chunked", "first"); err != nil {
		return err
	}
	upload := bytes.Repeat([]byte("u"), 2<<20)
	if err := expectStatus(client, http.MethodPost, "/uploads/archive", bytes.NewReader(upload), 200, "2097152"); err != nil {
		return err
	}
	request, _ := http.NewRequest(http.MethodPost, "http://traefik:8080/chunked-request", io.NopCloser(bytes.NewReader(upload[:4096])))
	request.ContentLength = -1
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || string(data) != "4096" {
		return fmt.Errorf("chunked request status=%d body=%q", response.StatusCode, data)
	}
	response, err = client.Get("http://traefik:8080/large-download")
	if err != nil {
		return err
	}
	count, _ := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || count != 2<<20 {
		return fmt.Errorf("large download status=%d bytes=%d", response.StatusCode, count)
	}
	for _, path := range []string{"/ws", "/api/websocket"} {
		if err := checkWebSocket(path); err != nil {
			return err
		}
	}
	return nil
}

func waitReady(client *http.Client) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := expectStatus(client, http.MethodGet, "/", nil, 200, "upstream"); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("Traefik compatibility route did not become ready")
}

func expectStatus(client *http.Client, method, path string, body io.Reader, status int, contains string, accepts ...string) error {
	request, _ := http.NewRequest(method, "http://traefik:8080"+path, body)
	if len(accepts) != 0 && accepts[0] != "" {
		request.Header.Set("Accept", accepts[0])
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 3<<20))
	if response.StatusCode != status || contains != "" && !bytes.Contains(data, []byte(contains)) {
		return fmt.Errorf("%s %s status=%d body=%q", method, path, response.StatusCode, data)
	}
	return nil
}

func checkStreaming(client *http.Client, path, expected string) error {
	started := time.Now()
	response, err := client.Get("http://traefik:8080" + path)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, expected) || time.Since(started) >= 100*time.Millisecond {
		return fmt.Errorf("%s was buffered: first=%q elapsed=%s", path, line, time.Since(started))
	}
	return nil
}

func websocketEcho(writer http.ResponseWriter, request *http.Request) {
	if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		http.Error(writer, "upgrade required", http.StatusBadRequest)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	accept := websocketAccept(request.Header.Get("Sec-WebSocket-Key"))
	_, _ = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	_ = buffer.Flush()
	for range webSocketSoakFrames {
		opcode, payload, err := readWebSocketFrame(buffer.Reader)
		if err != nil || opcode != 1 {
			return
		}
		if err := writeWebSocketFrame(buffer.Writer, payload); err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
	}
}

func websocketAccept(key string) string {
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func checkWebSocket(path string) error {
	connection, err := net.DialTimeout("tcp", "traefik:8080", time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(connection,
		"GET %s HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n",
		path, key,
	)
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		return fmt.Errorf("websocket %s status=%q err=%v", path, status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			break
		}
	}
	for frame := range webSocketSoakFrames {
		payload := []byte(fmt.Sprintf("ping-%02d", frame))
		if err := writeMaskedWebSocketFrame(connection, payload); err != nil {
			return err
		}
		opcode, echoed, err := readWebSocketFrame(reader)
		if err != nil || opcode != 1 || !bytes.Equal(echoed, payload) {
			return fmt.Errorf(
				"websocket %s frame=%d echo=%q opcode=%d err=%v",
				path, frame, echoed, opcode, err,
			)
		}
		time.Sleep(webSocketSoakDelay)
	}
	return nil
}

func readWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	length := int(header[1] & 0x7f)
	if length >= 126 {
		return 0, nil, errors.New("large harness WebSocket frame")
	}
	masked := header[1]&0x80 != 0
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(reader, mask); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	for index := range payload {
		if masked {
			payload[index] ^= mask[index%4]
		}
	}
	return header[0] & 0x0f, payload, nil
}

func writeWebSocketFrame(writer io.Writer, payload []byte) error {
	if len(payload) >= 126 {
		return errors.New("large harness WebSocket frame")
	}
	_, err := writer.Write(append([]byte{0x81, byte(len(payload))}, payload...))
	return err
}

func writeMaskedWebSocketFrame(writer io.Writer, payload []byte) error {
	if len(payload) >= 126 {
		return errors.New("large harness WebSocket frame")
	}
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for index, value := range payload {
		frame = append(frame, value^mask[index%4])
	}
	_, err := writer.Write(frame)
	return err
}
