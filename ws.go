package tradehub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ---------------------- Websocket manager (robust) ----------------------

// tuned websocket parameters
const (
	wsPingInterval   = 20 * time.Second
	wsPongTimeout    = 90 * time.Second
	wsWriteTimeout   = 10 * time.Second
	wsReadBufferSize = 1024 * 64
	wsWriteChanSize  = 128

	HeaderXSASVersion = "X-SAS-Version"
	HeaderUserAgent   = "User-Agent"
	HeaderAuth        = "Authorization"
	HeaderContentType = "Content-Type"

	XSASVersionValue = "2.0"

	SubscribeTypeToken     = "t"
	SubscribeTypeDepth     = "d"
	UnsubscribeTypeToken   = "u"
	UnsubscribeTypeDepth   = "ud"
	DefaultSubscriptionSep = "#"
)

const (
	DefaultBaseURL         = "https://ant.aliceblueonline.com/rest/AliceBlueAPIService/api/"
	DefaultContractCSVBase = "https://v2api.aliceblueonline.com/restpy/static/contract_master/%s.csv"
	DefaultWebsocketURL    = "wss://ant.aliceblueonline.com/order-notify/websocket"
	DefaultCreateWSURL     = "https://ant.aliceblueonline.com/order-notify/ws/createWsToken"
)

var endpointPaths = map[string]string{
	"encryption_key":  "customer/getAPIEncpkey",
	"getsessiondata":  "customer/getUserSID",
	"base_url_socket": "wss://ws1.aliceblueonline.com/NorenWS/",
}

type InstrumentWS struct {
	Exchange string `json:"exchange"`
	Token    string `json:"token"`
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Expiry   string `json:"expiry"`
	LotSize  string `json:"lot_size"`
}

type ClientWS struct {
	BaseURL         string
	ContractCSVBase string
	WebsocketURL    string
	CreateWSUrl     string

	APIName   string
	Version   string
	UserID    string
	APIKey    string
	SessionID string

	DisableSSL bool

	ENC           string
	wsConn        *websocket.Conn
	wsMutex       sync.Mutex
	writeChan     chan []byte
	Subscriptions string
	MarketDepth   bool

	wsDialer        *websocket.Dialer
	wsStop          context.CancelFunc
	wsStopped       chan struct{}
	wsReconnectChan chan struct{}

	isWSRunning int32 // atomic flag
	lastPong    int64 // unix nano of last pong

	SubscribeHandler func(message []byte)
	OnError          func(err error)
	OnOpen           func()
	OnClose          func()

	httpClient *http.Client
}

func (c *ClientWS) initWS() {
	if c.wsDialer == nil {
		c.wsDialer = &websocket.Dialer{
			Proxy:            websocket.DefaultDialer.Proxy,
			HandshakeTimeout: 15 * time.Second,
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: c.DisableSSL},
			NetDial: func(network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 60 * time.Second}
				return d.Dial(network, addr)
			},
			ReadBufferSize:  wsReadBufferSize,
			WriteBufferSize: wsReadBufferSize,
		}
	}
	if c.wsStopped == nil {
		c.wsStopped = make(chan struct{})
	}
	if c.wsReconnectChan == nil {
		c.wsReconnectChan = make(chan struct{}, 1)
	}
	c.wsMutex.Lock()
	if c.writeChan == nil {
		c.writeChan = make(chan []byte, wsWriteChanSize)
	}
	c.wsMutex.Unlock()
}

func SetCredentials(userID, apiKey string) *ClientWS {
	c := &ClientWS{
		BaseURL:         DefaultBaseURL,
		ContractCSVBase: DefaultContractCSVBase,
		WebsocketURL:    DefaultWebsocketURL,
		CreateWSUrl:     DefaultCreateWSURL,
		APIName:         ModuleUserAgentPrefix,
		Version:         DefaultVersion,
		UserID:          strings.ToUpper(userID),
		APIKey:          apiKey,
		httpClient:      &http.Client{Timeout: 15 * time.Second},
	}
	c.initWS()
	return c
}

func (c *ClientWS) invalidSess(sessionID string) (map[string]interface{}, error) {
	url := strings.TrimRight(c.BaseURL, "/") + "/ws/invalidateSocketSess"
	payload := map[string]string{"loginType": "API"}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderAuth, "Bearer "+c.UserID+" "+sessionID)
	req.Header.Set(HeaderContentType, "application/json")
	req.Header.Set(HeaderUserAgent, c.buildUserAgent())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error()}, err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ClientWS) createSession(sessionID string) (map[string]interface{}, error) {
	url := strings.TrimRight(c.BaseURL, "/") + "/ws/createSocketSess"
	payload := map[string]string{"loginType": "API"}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderAuth, "Bearer "+c.UserID+" "+sessionID)
	req.Header.Set(HeaderContentType, "application/json")
	req.Header.Set(HeaderUserAgent, c.buildUserAgent())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error()}, err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *ClientWS) endpointURL(key string) (string, error) {
	if p, ok := endpointPaths[key]; ok {
		return c.BaseURL + p, nil
	}
	return "", fmt.Errorf("unknown endpoint key %s", key)
}

func (c *ClientWS) helperRequest(method, url string, payload interface{}) (map[string]interface{}, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range c.standardHeaders(payload != nil) {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, err
	}
	defer resp.Body.Close()
	bs, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		emsg := fmt.Sprintf("%d - %s", resp.StatusCode, resp.Status)
		return map[string]interface{}{"stat": "Not_ok", "emsg": emsg, "encKey": nil}, fmt.Errorf(emsg)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(bs, &out); err != nil {
		var tmp interface{}
		if err2 := json.Unmarshal(bs, &tmp); err2 == nil {
			return map[string]interface{}{"result": tmp}, nil
		}
		return nil, err
	}
	return out, nil
}

func (c *ClientWS) postTo(key string, payload interface{}) (map[string]interface{}, error) {
	url, err := c.endpointURL(key)
	if err != nil {
		return nil, err
	}
	return c.helperRequest(http.MethodPost, url, payload)
}

func (c *ClientWS) GetSessionID() (map[string]interface{}, error) {
	resp, err := c.postTo("encryption_key", map[string]string{
		"userId": strings.ToUpper(c.UserID),
	})
	if err != nil {
		return resp, err
	}
	encKey, _ := resp["encKey"].(string)
	if encKey == "" {
		return resp, errors.New("encKey missing in response")
	}
	combined := strings.ToUpper(c.UserID) + c.APIKey + encKey
	hash := EncryptString(combined)
	payload := map[string]string{
		"userId":   strings.ToUpper(c.UserID),
		"userData": hash,
	}
	res, err := c.postTo("getsessiondata", payload)
	if err == nil {
		if stat, ok := res["stat"].(string); ok && stat == "Ok" {
			if sid, ok := res["sessionID"].(string); ok {
				c.SessionID = sid
			}
		}
	}
	fmt.Println("WS Seesion: ", c.SessionID)
	return res, err
}

// StartWebsocket starts the websocket manager and reconnect loop.
func (c *ClientWS) StartWebsocket(runInBackground bool, marketDepth bool) error {
	// Ensure session id exists and compute ENC as Python does
	if c.SessionID == "" {
		return fmt.Errorf("session id required...")
	}
	step1 := sha256.Sum256([]byte(c.SessionID))
	step1hex := fmt.Sprintf("%x", step1[:])
	step2 := sha256.Sum256([]byte(step1hex))
	c.ENC = fmt.Sprintf("%x", step2[:])

	// Invalidate & create socket session like Python does
	if invResp, invErr := c.invalidSess(c.SessionID); invErr != nil {
		if c.OnError != nil {
			c.OnError(fmt.Errorf("invalidSess error: %v; resp: %v", invErr, invResp))
		}
	} else {
		// Call createSession regardless of invResp content to mirror Python
		if createResp, createErr := c.createSession(c.SessionID); createErr != nil {
			if c.OnError != nil {
				c.OnError(fmt.Errorf("createSession error: %v; resp: %v", createErr, createResp))
			}
		}
	}

	if !atomic.CompareAndSwapInt32(&c.isWSRunning, 0, 1) {
		return fmt.Errorf("websocket manager already running")
	}
	c.initWS()
	c.MarketDepth = marketDepth

	ctx, cancel := context.WithCancel(context.Background())
	c.wsStop = cancel
	c.wsStopped = make(chan struct{})
	go c.wsManager(ctx)

	if runInBackground {
		return nil
	}
	return nil
}

func (c *ClientWS) closeWSConn() {
	c.wsMutex.Lock()
	defer c.wsMutex.Unlock()
	if c.wsConn != nil {
		_ = c.wsConn.Close()
		c.wsConn = nil
	}
	if c.writeChan != nil {
		close(c.writeChan)
		c.writeChan = nil
	}
}

func (c *ClientWS) startWritePump() {
	for msg := range c.writeChan {
		c.wsMutex.Lock()
		if c.wsConn == nil {
			c.wsMutex.Unlock()
			continue
		}
		_ = c.wsConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		err := c.wsConn.WriteMessage(websocket.TextMessage, msg)
		c.wsMutex.Unlock()
		if err != nil {
			if c.OnError != nil {
				c.OnError(err)
			}
			return
		}
	}
}

func (c *ClientWS) SendJSON(v interface{}) error {
	bs, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.wsMutex.Lock()
	defer c.wsMutex.Unlock()
	if c.writeChan == nil {
		return fmt.Errorf("write channel not initialized")
	}
	select {
	case c.writeChan <- bs:
		return nil
	default:
		return fmt.Errorf("write channel full")
	}
}

func (c *ClientWS) readPump(ctx context.Context) error {
	_ = c.wsConn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	for {
		_, msg, err := c.wsConn.ReadMessage()
		if err != nil {
			return err
		}
		_ = c.wsConn.SetReadDeadline(time.Now().Add(wsPongTimeout))
		if c.SubscribeHandler != nil {
			go func(m []byte) {
				defer func() {
					if r := recover(); r != nil {
						if c.OnError != nil {
							c.OnError(fmt.Errorf("subscribe handler panic: %v", r))
						}
					}
				}()
				c.SubscribeHandler(m)
			}(append([]byte(nil), msg...))
		}
	}
}

func (c *ClientWS) writePingLoop(ctx context.Context) error {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			last := time.Unix(0, atomic.LoadInt64(&c.lastPong))
			if time.Since(last) > wsPongTimeout {
				return fmt.Errorf("pong timeout: last pong %v ago", time.Since(last))
			}
			c.wsMutex.Lock()
			if c.wsConn != nil {
				_ = c.wsConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
				if err := c.wsConn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(wsWriteTimeout)); err != nil {
					c.wsMutex.Unlock()
					return err
				}
			}
			c.wsMutex.Unlock()
		}
	}
}

func (c *ClientWS) connectOnce(ctx context.Context) error {
	wsURL := c.WebsocketURL
	if alt, ok := endpointPaths["base_url_socket"]; ok && alt != "" {
		wsURL = alt
	}
	hdr := http.Header{}
	if c.SessionID != "" {
		hdr.Set("Authorization", "Bearer "+strings.ToUpper(c.UserID)+" "+c.SessionID)
	}
	hdr.Set("Content-Type", "application/json")

	conn, resp, err := c.wsDialer.Dial(wsURL, hdr)
	if err != nil {
		if resp != nil {
			body, _ := ioutil.ReadAll(resp.Body)
			return fmt.Errorf("websocket dial failed: %w (status %s, body: %s)", err, resp.Status, string(body))
		}
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	c.wsMutex.Lock()
	c.wsConn = conn
	if c.writeChan == nil {
		c.writeChan = make(chan []byte, wsWriteChanSize)
	}
	c.wsMutex.Unlock()

	atomic.StoreInt64(&c.lastPong, time.Now().UnixNano())

	c.wsConn.SetReadLimit(wsReadBufferSize)
	_ = c.wsConn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	c.wsConn.SetPongHandler(func(appData string) error {
		atomic.StoreInt64(&c.lastPong, time.Now().UnixNano())
		_ = c.wsConn.SetReadDeadline(time.Now().Add(wsPongTimeout))
		return nil
	})

	// start write pump
	go c.startWritePump()

	if c.OnOpen != nil {
		c.OnOpen()
	}

	initCon := map[string]interface{}{
		"susertoken": c.ENC,
		"t":          "c",
		"actid":      c.UserID + "_API",
		"uid":        c.UserID + "_API",
		"source":     "API",
	}
	if jb, err := json.Marshal(initCon); err == nil {
		fmt.Println("WebSocket initCon:", string(jb))
	}
	_ = c.SendJSON(initCon)

	ctx2, cancel2 := context.WithCancel(ctx)
	errCh := make(chan error, 2)

	go func() { errCh <- c.readPump(ctx2) }()
	go func() { errCh <- c.writePingLoop(ctx2) }()

	select {
	case <-ctx.Done():
		cancel2()
		c.closeWSConn()
		return nil
	case e := <-errCh:
		cancel2()
		c.closeWSConn()
		// drain writeChan to avoid blocking goroutines
		go func() {
			c.wsMutex.Lock()
			if c.writeChan != nil {
				close(c.writeChan)
				c.writeChan = nil
			}
			c.wsMutex.Unlock()
		}()
		if c.OnClose != nil {
			c.OnClose()
		}
		if websocket.IsCloseError(e, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			return nil
		}
		return fmt.Errorf("websocket pump error: %w", e)
	}
}

func (c *ClientWS) wsManager(ctx context.Context) {
	defer func() {
		c.closeWSConn()
		close(c.wsStopped)
		atomic.StoreInt32(&c.isWSRunning, 0)
		if c.OnClose != nil {
			c.OnClose()
		}
	}()

	backoffBase := 1.0
	maxBackoff := 60.0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		err := c.connectOnce(ctx)
		if err == nil {
			// connection ended gracefully or ctx canceled
		} else {
			if c.OnError != nil {
				c.OnError(err)
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		sleep := backoffBase + rng.Float64()*0.5
		if sleep > maxBackoff {
			sleep = maxBackoff
		}
		time.Sleep(time.Duration(sleep) * time.Second)
		backoffBase = math.Min(maxBackoff, backoffBase*2)
	}
}

func (c *ClientWS) StopWebsocket() {
	if atomic.LoadInt32(&c.isWSRunning) == 0 {
		return
	}
	if c.wsStop != nil {
		c.wsStop()
	}
	select {
	case <-c.wsStopped:
	case <-time.After(5 * time.Second):
	}
	atomic.StoreInt32(&c.isWSRunning, 0)
}

func (c *ClientWS) Subscribe(instruments []InstrumentWS) error {
	scripts := []string{}
	for _, ins := range instruments {
		scripts = append(scripts, fmt.Sprintf("%s|%s", ins.Exchange, ins.Token))
	}
	c.Subscriptions = strings.Join(scripts, DefaultSubscriptionSep)
	t := SubscribeTypeToken
	if c.MarketDepth {
		t = SubscribeTypeDepth
	}
	data := map[string]interface{}{"k": c.Subscriptions, "t": t}
	return c.SendJSON(data)
}

func (c *ClientWS) Unsubscribe(instruments []InstrumentWS) error {
	scripts := []string{}
	for _, ins := range instruments {
		scripts = append(scripts, fmt.Sprintf("%s|%s", ins.Exchange, ins.Token))
	}
	t := UnsubscribeTypeToken
	if c.MarketDepth {
		t = UnsubscribeTypeDepth
	}
	data := map[string]interface{}{"k": strings.Join(scripts, DefaultSubscriptionSep), "t": t}
	return c.SendJSON(data)
}

// ---------------------- Small helpers ----------------------

func EncryptString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

func (c *ClientWS) buildUserAgent() string {
	return c.APIName + c.Version
}

func (c *ClientWS) buildAuthHeader() string {
	if c.SessionID != "" {
		return "Bearer " + strings.ToUpper(c.UserID) + " " + c.SessionID
	}
	return ""
}

func (c *ClientWS) standardHeaders(contentType bool) map[string]string {
	h := map[string]string{
		HeaderXSASVersion: XSASVersionValue,
		HeaderUserAgent:   c.buildUserAgent(),
	}
	if auth := c.buildAuthHeader(); auth != "" {
		h[HeaderAuth] = auth
	}
	if contentType {
		h[HeaderContentType] = "application/json"
	}
	return h
}

// ---------------------- Helpers ----------------------

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (c *ClientWS) loadContractCSV(exchange string) ([]map[string]string, error) {
	filePath := fmt.Sprintf("%s.csv", exchange)
	records, err := readCSVNormalized(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			if dlErr := c.DownloadContractMaster(exchange); dlErr != nil {
				return nil, dlErr
			}
			return readCSVNormalized(filePath)
		}
		return nil, err
	}
	return records, nil
}

func readCSVNormalized(filePath string) ([]map[string]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 1 {
		return nil, errors.New("empty csv")
	}
	headers := records[0]
	normalizedHeaders := make([]string, len(headers))
	for i, h := range headers {
		normalizedHeaders[i] = strings.ToLower(strings.TrimSpace(h))
	}
	out := make([]map[string]string, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		row := records[i]
		m := map[string]string{}
		for j := 0; j < len(normalizedHeaders) && j < len(row); j++ {
			m[normalizedHeaders[j]] = strings.TrimSpace(row[j])
		}
		out = append(out, m)
	}
	return out, nil
}

func (c *ClientWS) DownloadContractMaster(exchange string) error {
	url := fmt.Sprintf(c.ContractCSVBase, strings.ToUpper(exchange))
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: %d", resp.StatusCode)
	}
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("%s.csv", strings.ToUpper(exchange))
	return ioutil.WriteFile(fileName, bs, 0644)
}

func (c *ClientWS) GetInstrumentByTokenWS(exchange, token string) (InstrumentWS, error) {
	records, err := c.loadContractCSV(exchange)
	if err != nil {
		return InstrumentWS{}, err
	}
	if strings.ToUpper(exchange) == "INDICES" {
		for _, r := range records {
			if r["token"] == token {
				return InstrumentWS{Exchange: r["exch"], Token: r["token"], Symbol: r["symbol"]}, nil
			}
		}
		return InstrumentWS{}, errors.New("token not found in indices")
	}
	for _, r := range records {
		if r["token"] == token {
			inst := InstrumentWS{
				Exchange: firstNonEmpty(r["exch"]),
				Token:    firstNonEmpty(r["token"]),
				Symbol:   firstNonEmpty(r["symbol"]),
				Name:     firstNonEmpty(r["trading symbol"], r["formattedinsname"]),
				Expiry:   firstNonEmpty(r["expiry date"], r["expirydate"]),
				LotSize:  firstNonEmpty(r["lot size"], r["lotsize"]),
			}
			return inst, nil
		}
	}
	return InstrumentWS{}, errors.New("token not found")
}
