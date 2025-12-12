package tradehub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type (
	Dispatcher struct {
		Ch chan string
	}
)

const (
	WebSocketURL            = "wss://ws1.aliceblueonline.com/NorenWS/"
	InvalidateSessionAPIURL = BaseURL + "/open-api/od/v1/profile/invalidateWsSess"
	CreateSessionAPIURL     = BaseURL + "/open-api/od/v1/profile/createWsSess"

	maxRedirects = 5
	ReadTimeout  = 60 * time.Second
	PingInterval = 50 * time.Second
)

// ----------------------- API STRUCTS -----------------------

type InvalidateSessionRequest struct {
	Source string `json:"source"`
	UserID string `json:"userId"`
}

type InvalidateSessionResponse struct {
	Status      string      `json:"status"`
	Message     string      `json:"message"`
	InfoMessage interface{} `json:"infoMessage"`
	Result      []struct {
		Status string `json:"Status"`
	} `json:"result"`
}

// ----------------------- HTTP HELPERS -----------------------

func InvalidateWebSocketSession(userID, authToken string) (string, error) {
	payload := InvalidateSessionRequest{Source: "API", UserID: userID}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("POST", InvalidateSessionAPIURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bs, _ := io.ReadAll(resp.Body)
	return string(bs), nil
}

func CreateWebSocketSession(userID, authToken string) (string, error) {
	payload := InvalidateSessionRequest{Source: "API", UserID: userID}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("POST", CreateSessionAPIURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bs, _ := io.ReadAll(resp.Body)
	return string(bs), nil
}

// ----------------------- SHA / TOKEN HELPERS -----------------------

func CreateSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func GenerateSuserToken(sessionID string) string {
	return CreateSHA256(CreateSHA256(sessionID))
}

// ----------------------- URL / REDIRECT HELPERS -----------------------

func resolveLocation(baseStr, loc string) (string, error) {
	if strings.HasPrefix(loc, "ws://") || strings.HasPrefix(loc, "wss://") ||
		strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc, nil
	}
	baseURL, _ := url.Parse(baseStr)
	locURL, _ := url.Parse(loc)
	return baseURL.ResolveReference(locURL).String(), nil
}

func convertHTTPToWS(u string) string {
	if strings.HasPrefix(u, "https://") {
		return "wss://" + strings.TrimPrefix(u, "https://")
	}
	if strings.HasPrefix(u, "http://") {
		return "ws://" + strings.TrimPrefix(u, "http://")
	}
	return u
}

// ----------------------- LOW LEVEL WEBSOCKET CONNECT -----------------------

func dialFollow(wsURL string, headers http.Header) (*websocket.Conn, *http.Response, error) {
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: false},
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 15 * time.Second,
	}

	current := wsURL
	for attempt := 0; attempt <= maxRedirects; attempt++ {
		conn, resp, err := dialer.Dial(current, headers)
		if err == nil {
			return conn, resp, nil
		}

		if resp != nil {
			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
				newURL, _ := resolveLocation(current, loc)
				newURL = convertHTTPToWS(newURL)
				current = newURL
				continue
			}
			return nil, resp, err
		}

		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("max redirects exceeded")
}

// ----------------------- HIGH LEVEL CONNECT (LOGIN) -----------------------

func ConnectWS(sessionID, clientID string) (*websocket.Conn, error) {
	login := map[string]string{
		"susertoken": GenerateSuserToken(sessionID),
		"t":          "c",
		"actid":      clientID + "_API",
		"uid":        clientID + "_API",
		"source":     "API",
	}
	loginBs, _ := json.Marshal(login)

	headers := http.Header{}
	headers.Set("Origin", BaseURL)
	headers.Set("User-Agent", "Go-WS-Client")

	conn, resp, err := dialFollow(WebSocketURL, headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("connect failed (%d): %v", resp.StatusCode, err)
		}
		return nil, err
	}

	// send login
	conn.WriteMessage(websocket.TextMessage, loginBs)

	// read login reply
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("login read error: %v", err)
	}

	var m map[string]any
	_ = json.Unmarshal(msg, &m)

	isOK := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		return strings.EqualFold(s, "OK") || strings.EqualFold(s, "SUCCESS")
	}

	if isOK(m["k"]) || isOK(m["s"]) || m["uid"] != nil {
		return conn, nil
	}

	conn.Close()
	return nil, fmt.Errorf("login failed: %s", string(msg))
}

// ----------------------- DISPATCHER (SINGLE READER) -----------------------

func StartDispatcher(ctx context.Context, conn *websocket.Conn, buf int) *Dispatcher {
	ch := make(chan string, buf)

	_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))
		return nil
	})

	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, msg, err := conn.ReadMessage()
				if err != nil {
					log.Println("read error:", err)
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(ReadTimeout))
				ch <- string(msg)
			}
		}
	}()

	return &Dispatcher{Ch: ch}
}

// ----------------------- KEEPALIVE -----------------------

func KeepAlive(ctx context.Context, conn *websocket.Conn, interval time.Duration, sendHeartbeat bool, status chan<- string) {
	t := time.NewTicker(interval)
	defer t.Stop()

	heartbeat := []byte(`{"k":"","t":"h"}`)

	for {
		select {
		case <-ctx.Done():
			status <- "KeepAlive stopped"
			return

		case <-t.C:
			// Send ping
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				status <- fmt.Sprintf("Ping error: %v", err)
				return
			}
			status <- "Ping sent"

			// Send heartbeat JSON frame
			if sendHeartbeat {
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, heartbeat); err != nil {
					status <- fmt.Sprintf("Heartbeat error: %v", err)
					return
				}
				status <- "Heartbeat sent"
			}
		}
	}
}

// ----------------------- SUBSCRIBE / UNSUBSCRIBE -----------------------

func Subscribe(conn *websocket.Conn, symbols string, typ string) error {
	req := map[string]string{"k": symbols, "t": typ}
	bs, _ := json.Marshal(req)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, bs)
}

func Unsubscribe(conn *websocket.Conn, symbols string, typ string) error {
	req := map[string]string{"k": symbols, "t": typ}
	bs, _ := json.Marshal(req)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, bs)
}

// Convenience wrappers
func SubscribeMarketData(conn *websocket.Conn, symbols string) error {
	return Subscribe(conn, symbols, "t")
}
func UnsubscribeMarketData(conn *websocket.Conn, symbols string) error {
	return Unsubscribe(conn, symbols, "u")
}
func SubscribeDepthData(conn *websocket.Conn, symbols string) error {
	return Subscribe(conn, symbols, "d")
}
func UnsubscribeDepthData(conn *websocket.Conn, symbols string) error {
	return Unsubscribe(conn, symbols, "ud")
}

// ----------------------- CLOSE CONNECTION -----------------------

func Close(conn *websocket.Conn) error {
	if conn == nil {
		return nil
	}
	conn.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"),
	)
	return conn.Close()
}
