package tradehub

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	ExchangeNSE     Exchange = "NSE"
	ExchangeBSE     Exchange = "BSE"
	ExchangeNFO     Exchange = "NFO"
	ExchangeBFO     Exchange = "BFO"
	ExchangeCDS     Exchange = "CDS"
	ExchangeBCD     Exchange = "BCD"
	ExchangeNCO     Exchange = "NCO"
	ExchangeBCO     Exchange = "BCO"
	ExchangeMCX     Exchange = "MCX"
	ExchangeINDICES Exchange = "INDICES"
	ExchangeNCDEX   Exchange = "NCDEX"
)

func (e Exchange) String() string { return string(e) }

// TransactionType values
type TransactionType string

const (
	TransactionBuy  TransactionType = "BUY"
	TransactionSell TransactionType = "SELL"
)

func (t TransactionType) String() string { return string(t) }

// OrderComplexity values
type OrderComplexity string

const (
	OrderComplexityRegular OrderComplexity = "REGULAR"
	OrderComplexityAMO     OrderComplexity = "AMO"
	OrderComplexityCover   OrderComplexity = "CO"
	OrderComplexityBracket OrderComplexity = "BO"
)

func (oc OrderComplexity) String() string { return string(oc) }

// ProductType values
type ProductType string

const (
	ProductNormal   ProductType = "NORMAL"
	ProductIntraday ProductType = "INTRADAY"
	ProductLongterm ProductType = "LONGTERM"
	ProductDelivery ProductType = "DELIVERY"
	ProductBNPL     ProductType = "BNPL"
	ProductMTF      ProductType = "MTF"
	ProductGTT      ProductType = "GTT"
	ProductCNC      ProductType = "CNC"
	ProductMIS      ProductType = "MIS"
)

func (p ProductType) String() string { return string(p) }

// OrderType values
type OrderType string

const (
	OrderTypeLimit       OrderType = "LIMIT"
	OrderTypeMarket      OrderType = "MARKET"
	OrderTypeStopLoss    OrderType = "SL"
	OrderTypeStopLossMkt OrderType = "SLM"
)

func (ot OrderType) String() string { return string(ot) }

// PositionType values
type PositionType string

const (
	PositionDay PositionType = "DAY"
	PositionNet PositionType = "NET"
	PositionIOC PositionType = "IOC"
)

func (pt PositionType) String() string { return string(pt) }

// OrderSource values
type OrderSource string

const (
	OrderSourceWEB OrderSource = "WEB"
	OrderSourceAPI OrderSource = "API"
	OrderSourceMOB OrderSource = "MOB"
)

func (os OrderSource) String() string { return string(os) }

type Exchange string

// ------------------------- Validation -------------------------

type Validator struct{}

func (v Validator) IsEmpty(value string, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty string", fieldName)
	}
	return nil
}

func (v Validator) IsNotEmpty(value string, fieldName string) error {
	if value != "" {
		return fmt.Errorf("%s must be empty string", fieldName)
	}
	return nil
}

func (v Validator) IsNone(ok bool, fieldName string) error {
	// In Go we represent 'none' by a boolean flag caller passes: ok==false => missing
	if !ok {
		return fmt.Errorf("%s is required and cannot be None", fieldName)
	}
	return nil
}

func (v Validator) IsPosNum(value interface{}, fieldName string) error {
	switch t := value.(type) {
	case int:
		if t <= 0 {
			return fmt.Errorf("%s must be greater than zero", fieldName)
		}
	case int64:
		if t <= 0 {
			return fmt.Errorf("%s must be greater than zero", fieldName)
		}
	case float64:
		if t <= 0 {
			return fmt.Errorf("%s must be greater than zero", fieldName)
		}
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err != nil || f <= 0 {
			return fmt.Errorf("%s must be a valid number greater than zero", fieldName)
		}
	default:
		return fmt.Errorf("%s must be a valid number greater than zero", fieldName)
	}
	return nil
}

// Helper to validate map[string]string existence/non-empty
func ValidateNone(m map[string]string) error {
	for k, v := range m {
		if v == "" {
			return fmt.Errorf("%s is required and cannot be None/empty", k)
		}
	}
	return nil
}

// ------------------------- checksum (from checksum) -------------------------

func GenerateChecksum(userID, authCode, secretKey string) (string, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(authCode) == "" || strings.TrimSpace(secretKey) == "" {
		return "", errors.New("user_id, auth_Code and secret_key are required and cannot be empty")
	}
	concat := fmt.Sprintf("%s%s%s", userID, authCode, secretKey)
	sum := sha256.Sum256([]byte(concat))
	return hex.EncodeToString(sum[:]), nil
}

// ------------------------- timestamp (from timestamp) -------------------------

func ToEpoch(value string, isStart bool) (int64, error) {
	layoutFull := "2006-01-02 15:04:05"
	layoutDate := "2006-01-02"
	if t, err := time.Parse(layoutFull, value); err == nil {
		return t.Unix(), nil
	} else {
		// try date only
		if d, err2 := time.Parse(layoutDate, value); err2 == nil {
			if isStart {
				dt := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.Local)
				return dt.Unix(), nil
			} else {
				dt := time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, time.Local)
				return dt.Unix(), nil
			}
		} else {
			return 0, errors.New("Invalid date format. Use 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'")
		}
	}
}

// ------------------------- device identifier (from device_identifier) -------------------------

func GetDeviceID() string {
	platform := runtimeGOOS()
	switch platform {
	case "windows":
		// try wmic
		out, err := exec.Command("wmic", "bios", "get", "serialnumber").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 1 {
				serial := strings.TrimSpace(lines[1])
				if serial != "" {
					return serial
				}
			}
		}
	case "linux":
		if exists("/etc/machine-id") {
			if b, err := ioutil.ReadFile("/etc/machine-id"); err == nil {
				return strings.TrimSpace(string(b))
			}
		}
		if exists("/var/lib/dbus/machine-id") {
			if b, err := ioutil.ReadFile("/var/lib/dbus/machine-id"); err == nil {
				return strings.TrimSpace(string(b))
			}
		}
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err == nil {
			s := string(out)
			// fallback parse for IOPlatformUUID
			idx := strings.Index(s, "IOPlatformUUID")
			if idx >= 0 {
				parts := strings.Split(s, "\"")
				if len(parts) > 1 {
					return parts[len(parts)-2]
				}
			}
		}
	}
	// fallback: use MAC-like node id
	return fallbackHexNode()
}

func fallbackHexNode() string {
	// simple fallback — use hostname hashed
	if h, err := os.Hostname(); err == nil {
		sum := sha256.Sum256([]byte(h))
		return hex.EncodeToString(sum[:8]) // short
	}
	return "unknown-device"
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// runtimeGOOS simple wrapper so tests can stub if required
func runtimeGOOS() string {
	return strings.ToLower(os.Getenv("GOOS_OVERRIDE"))
	// If not overridden, rely on runtime.GOOS — but to avoid importing runtime in this snippet, fallback:
	// In a real project use runtime.GOOS
}

// ------------------------- config & settings (from config & settings) -------------------------

const (
	ModuleUserAgentPrefix = "Codifi API Connect - Go Lib "
	DefaultVersion        = "1.0.0-go"
)

var (
	BaseURL            = "https://a3.aliceblueonline.com/"
	APIName            = "Codifi ProTrade - Go Library"
	ContractBaseURL    = "https://v2api.aliceblueonline.com/restpy/static/contract_master/%s.csv"
	GetVendorSession   = "open-api/od/v1/vendor/getUserDetails"
	GetProfile         = "open-api/od/v1/profile/"
	GetFunds           = "open-api/od/v1/limits/"
	GetPositions       = "open-api/od/v1/positions"
	GetHoldings        = "open-api/od/v1/holdings"
	PositionConversion = "open-api/od/v1/conversion"
	SingleOrderMargin  = "open-api/od/v1/orders/checkMargin"
	OrderExecute       = "open-api/od/v1/orders/placeorder"
	OrderModify        = "open-api/od/v1/orders/modify"
	OrderCancel        = "open-api/od/v1/orders/cancel"
	ExitBracketOrder   = "open-api/od/v1/orders/exit/sno"
	PositionSqrOff     = "open-api/od/v1/orders/positions/sqroff"
	GTTOrderExecute    = "open-api/od/v1/orders/gtt/execute"
	GTTOrderModify     = "open-api/od/v1/orders/gtt/modify"
	GTTOrderCancel     = "open-api/od/v1/orders/gtt/cancel"
	GetOrderBook       = "open-api/od/v1/orders/book"
	GetTradeBook       = "open-api/od/v1/orders/trades"
	GetOrderHistory    = "open-api/od/v1/orders/history"
	GetGTTOrderBook    = "open-api/od/v1/orders/gtt/orderbook"
	GetChartHistory    = "" // placeholder
)

// ------------------------- RequestHandler (from api_client) -------------------------

type RequestHandler struct {
	AuthHeader string
	Client     *http.Client
}

func NewRequestHandler(sessionToken string) *RequestHandler {
	return &RequestHandler{
		AuthHeader: sessionToken,
		Client:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (rh *RequestHandler) Request(url, method string, data interface{}, params map[string]string) (map[string]interface{}, error) {
	method = strings.ToUpper(method)
	var body io.Reader = nil
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(b)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if rh.AuthHeader != "" {
		req.Header.Set("Authorization", rh.AuthHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	// add params if present
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := rh.Client.Do(req)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var res map[string]interface{}
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&res); err != nil {
			// if not JSON, return text
			b, _ := ioutil.ReadAll(resp.Body)
			return map[string]interface{}{"stat": "Ok", "result": string(b)}, nil
		}
		return res, nil
	} else {
		return map[string]interface{}{"stat": "Not_ok", "emsg": fmt.Sprintf("%d - %s", resp.StatusCode, resp.Status), "encKey": nil}, nil
	}
}

// ------------------------- CSV contract_read (from file_read) -------------------------

// Minimal CSV contract reader that performs limited conversions.
func ContractRead(exch string) ([]map[string]string, error) {
	fname := fmt.Sprintf("%s.csv", strings.ToUpper(exch))
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := records[0]
	out := make([]map[string]string, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		row := records[i]
		// skip completely empty rows
		allEmpty := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}
		m := make(map[string]string)
		for j, col := range header {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			colNorm := strings.TrimSpace(col)

			m[colNorm] = strings.TrimSpace(val)
		}
		out = append(out, m)
	}
	return out, nil
}

// ------------------------- Instrument types & enums -------------------------

type Instrument struct {
	Exchange      string
	Token         string
	Symbol        string
	TradingSymbol string
	Expiry        string
	LotSize       string
}

// ------------------------- TradeHub (core) -------------------------

type TradeHub struct {
	UserID          string
	AuthCode        string
	SecretKey       string
	BaseURL         string
	BaseURLContract string
	SessionID       string
	Endpoints       map[string]string
}

func NewTradeHub(userID, authCode, secretKey, baseURL string) *TradeHub {
	if baseURL == "" {
		baseURL = BaseURL
	}
	th := &TradeHub{
		UserID:          strings.ToUpper(userID),
		AuthCode:        authCode,
		SecretKey:       secretKey,
		BaseURL:         baseURL,
		BaseURLContract: ContractBaseURL,
		Endpoints: map[string]string{
			"getSession":      GetVendorSession,
			"getProfile":      GetProfile,
			"getFunds":        GetFunds,
			"getPositions":    GetPositions,
			"getHoldings":     GetHoldings,
			"posConversion":   PositionConversion,
			"SingleOrdMargin": SingleOrderMargin,
			"ordExecute":      OrderExecute,
			"ordModify":       OrderModify,
			"ordCancel":       OrderCancel,
			"ordExitBracket":  ExitBracketOrder,
			"positionSqrOff":  PositionSqrOff,
			"ordGTT_Execute":  GTTOrderExecute,
			"ordGTT_Modify":   GTTOrderModify,
			"ordGTT_Cancel":   GTTOrderCancel,
			"getOrderbook":    GetOrderBook,
			"getTradebook":    GetTradeBook,
			"getOrdHistory":   GetOrderHistory,
			"getGTTOrderbook": GetGTTOrderBook,
			"getChartHistory": GetChartHistory,
		},
	}
	return th
}

func (th *TradeHub) initSession() *RequestHandler {
	return NewRequestHandler(th.SessionAuthorization())
}

func (th *TradeHub) SessionAuthorization() string {
	if th.SessionID != "" {
		return "Bearer " + th.SessionID
	}
	return ""
}

func (th *TradeHub) endpointURL(key string, pathParameter string) (string, error) {
	end, ok := th.Endpoints[key]
	if !ok {
		return "", fmt.Errorf("Invalid endpoint key: %s", key)
	}
	url := th.BaseURL + end
	if pathParameter != "" {
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		url += pathParameter
	}
	return url, nil
}

func (th *TradeHub) InitPost(key string, data interface{}, params map[string]string, pathParameter string) (map[string]interface{}, error) {
	url, err := th.endpointURL(key, pathParameter)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	api := th.initSession()
	return api.Request(url, "POST", data, params)
}

func (th *TradeHub) InitGet(key string, params map[string]string, pathParameter string) (map[string]interface{}, error) {
	url, err := th.endpointURL(key, pathParameter)
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	api := th.initSession()
	return api.Request(url, "GET", nil, params)
}

func (th *TradeHub) GetHoldings(product string) (map[string]interface{}, error) {
	endpointKey := "getHoldings" // MUST match config key exactly

	pathParam := product

	resp, err := th.InitGet(endpointKey, nil, pathParam)
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

// ------------------------- get_session_id (adapted) -------------------------

func (th *TradeHub) GetSessionID(checksumIn string, sessionIn string) (map[string]interface{}, error) {
	if sessionIn != "" {
		th.SessionID = strings.TrimSpace(sessionIn)
		return map[string]interface{}{"userSession": th.SessionID}, nil
	}

	var checksum string
	if strings.TrimSpace(checksumIn) == "" {
		cs, err := GenerateChecksum(th.UserID, th.AuthCode, th.SecretKey)
		if err != nil {
			return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
		}
		checksum = cs
	} else {
		checksum = strings.TrimSpace(checksumIn)
	}

	data := map[string]string{"checkSum": checksum}
	resp, err := th.InitPost("getSession", data, nil, "")
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	// Handle possible shapes
	if respStat, ok := resp["stat"].(string); ok && (respStat == "Ok" || respStat == "ok") {
		// Try userSession field
		if us, ok2 := resp["userSession"].(string); ok2 && us != "" {
			th.SessionID = us
			return map[string]interface{}{"userSession": th.SessionID}, nil
		}
		// Try result array containing accessToken
		if result, ok3 := resp["result"].([]interface{}); ok3 && len(result) > 0 {
			if first, ok4 := result[0].(map[string]interface{}); ok4 {
				if token, ok5 := first["accessToken"].(string); ok5 {
					th.SessionID = token
					return map[string]interface{}{"userSession": th.SessionID}, nil
				}
			}
		}
		return map[string]interface{}{"stat": "Not_ok", "emsg": "Session ID not found in response", "encKey": nil}, nil
	} else {
		return resp, nil
	}
}

// ------------------------- get_contract_master (simplified) -------------------------

func (th *TradeHub) GetContractMaster(exchange string) (map[string]interface{}, error) {
	exchange = strings.ToUpper(exchange)
	if exchange != "INDICES" && exchange != "NCDEX" && len(exchange) != 3 {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "Invalid Exchange parameter", "encKey": nil}, nil
	}
	now := time.Now()
	if now.Hour() >= 8 {
		candidates := []string{
			strings.ToLower(exchange),
			strings.ToLower(exchange) + ".csv",
			strings.ToLower(exchange) + ".CSV",
			strings.ToUpper(exchange),
			strings.ToUpper(exchange) + ".csv",
			strings.ToUpper(exchange) + ".CSV",
		}
		for _, c := range candidates {
			url := th.BaseURLContract + c
			resp, err := http.Get(url)
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 {
				body, _ := ioutil.ReadAll(resp.Body)
				fname := fmt.Sprintf("%s.csv", strings.ToUpper(exchange))
				_ = ioutil.WriteFile(fname, body, 0644)
				return map[string]interface{}{"stat": "Ok", "emsg": "Today's contract file downloaded"}, nil
			}
		}
		return map[string]interface{}{"stat": "Ok", "emsg": "Failed to download today's contract file"}, nil
	} else {
		return map[string]interface{}{"stat": "Ok", "emsg": "Previous day contract file saved"}, nil
	}
}

// ------------------------- get_instrument (simplified) -------------------------
/*
func (th *TradeHub) GetInstrument(exchange string, symbol string, token string) (interface{}, error) {
	if symbol == "" && token == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "Either symbol or token must be provided", "encKey": nil}, nil
	}
	contract, err := ContractRead(exchange)
	if err != nil {
		// try download contract and read again
		_, _ = th.GetContractMaster(exchange)
		contract, err = ContractRead(exchange)
		if err != nil {
			return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
		}
	}
	// normalize keys lower-case for comparison
	for _, row := range contract {
		// handle INDICES vs others
		if strings.ToUpper(exchange) == "INDICES" {
			if token != "" && row["Token"] == token {
				inst := Instrument{Exchange: row["Exch"], Token: row["Token"], Symbol: row["Symbol"], TradingSymbol: "", Expiry: "", LotSize: ""}
				return inst, nil
			}
			if symbol != "" && strings.ToUpper(row["Symbol"]) == strings.ToUpper(symbol) {
				inst := Instrument{Exchange: row["Exch"], Token: row["Token"], Symbol: row["Symbol"], TradingSymbol: "", Expiry: "", LotSize: ""}
				return inst, nil
			}
		} else {
			if token != "" && row["Token"] == token {
				inst := Instrument{Exchange: row["Exch"], Token: row["Token"], Symbol: row["Symbol"], TradingSymbol: row["Trading Symbol"], Expiry: row["Expiry Date"], LotSize: row["Lot Size"]}
				return inst, nil
			}
			if symbol != "" && (strings.ToUpper(row["Symbol"]) == strings.ToUpper(symbol) || strings.ToUpper(row["Trading Symbol"]) == strings.ToUpper(symbol)) {
				inst := Instrument{Exchange: row["Exch"], Token: row["Token"], Symbol: row["Symbol"], TradingSymbol: row["Trading Symbol"], Expiry: row["Expiry Date"], LotSize: row["Lot Size"]}
				return inst, nil
			}
		}
	}
	return map[string]interface{}{"stat": "Not_ok", "emsg": "The symbol is not available in this exchange", "encKey": nil}, nil
}*/

// GetInstrument mirrors
// Accepts exchange (like "NSE","MCX","NFO","INDICES"), symbol (optional) and token (optional).
// Returns either Instrument (on success) or a map[string]interface{} error

func getStringValue(v interface{}) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)

	case *string:
		if val == nil {
			return ""
		}
		return strings.TrimSpace(*val)

	case fmt.Stringer:
		// Handles enums that implement String() → "NSE"
		return strings.TrimSpace(val.String())

	case int, int32, int64, float32, float64:
		s := fmt.Sprintf("%v", val)
		// Normalize cases like "12345.0"
		if strings.HasSuffix(s, ".0") {
			s = strings.TrimSuffix(s, ".0")
		}
		return s

	default:
		// fallback: best effort
		s := fmt.Sprintf("%v", val)
		return strings.TrimSpace(s)
	}
}

func (th *TradeHub) GetInstrument(exchange string, symbol string, token interface{}) (interface{}, error) {
	// Normalize exchange (handle enum-like inputs)
	exchange = strings.TrimSpace(getStringValue(exchange))
	if exchange == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "exchange is required", "encKey": nil}, nil
	}

	// Helper to normalize token input (could be int, float-like, or string)
	normalizeToken := func(t interface{}) string {
		if t == nil {
			return ""
		}
		switch v := t.(type) {
		case string:
			s := strings.TrimSpace(v)
			// strip trailing .0 if present
			if strings.HasSuffix(s, ".0") {
				s = strings.TrimSuffix(s, ".0")
			}
			return s
		case int, int64:
			return fmt.Sprintf("%v", v)
		case float32, float64:
			// handle numbers like 12345.0 -> "12345"
			f := fmt.Sprintf("%v", v)
			if strings.HasSuffix(f, ".0") {
				return strings.TrimSuffix(f, ".0")
			}
			return f
		default:
			return fmt.Sprintf("%v", v)
		}
	}

	tokenStr := normalizeToken(token)
	symbolUpper := strings.ToUpper(strings.TrimSpace(symbol))

	// Try to read contract; if missing, try to download contract master
	contracts, err := ContractRead(strings.ToUpper(exchange))
	if err != nil || len(contracts) == 0 {
		// Try to download contract master and read again
		_, _ = th.GetContractMaster(strings.ToUpper(exchange))
		contracts, err = ContractRead(strings.ToUpper(exchange))
		if err != nil {
			// If still error, return error response
			return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
		}
	}

	// Helper to get map values case-insensitively
	getVal := func(row map[string]string, keys ...string) string {
		for _, k := range keys {
			if v, ok := row[k]; ok && strings.TrimSpace(v) != "" {
				return v
			}
			// try lowercase form
			kl := strings.ToLower(k)
			for rk, rv := range row {
				if strings.ToLower(rk) == kl && strings.TrimSpace(rv) != "" {
					return rv
				}
			}
		}
		return ""
	}

	// Special handling for INDICES
	if strings.EqualFold(exchange, "INDICES") {
		// filter by token if provided, else by symbol (uppercased)
		for _, row := range contracts {
			if tokenStr != "" {
				if tok := getVal(row, "token", "Token"); tok != "" && tok == tokenStr {
					inst := Instrument{
						Exchange:      getVal(row, "exch", "Exch", "Exchange", "exchange"),
						Token:         tok,
						Symbol:        getVal(row, "symbol", "Symbol"),
						TradingSymbol: "",
						Expiry:        "",
						LotSize:       "",
					}
					return inst, nil
				}
			} else if symbolUpper != "" {
				if sym := getVal(row, "symbol", "Symbol"); strings.ToUpper(sym) == symbolUpper {
					inst := Instrument{
						Exchange:      getVal(row, "exch", "Exch", "Exchange", "exchange"),
						Token:         getVal(row, "token", "Token"),
						Symbol:        sym,
						TradingSymbol: "",
						Expiry:        "",
						LotSize:       "",
					}
					return inst, nil
				}
			}
		}
		return map[string]interface{}{"stat": "Not_ok", "emsg": "The symbol is not available in this exchange", "encKey": nil}, nil
	}

	// Non-indices: check Token or Symbol/Trading Symbol
	for _, row := range contracts {
		// If token provided, prefer exact token match
		if tokenStr != "" {
			tok := getVal(row, "Token", "token")
			// normalize token forms like "12345.0"
			if tok != "" {
				ntok := normalizeToken(tok)
				if ntok == tokenStr {
					expiry := getVal(row, "Expiry Date", "expiry_date", "Expiry", "expiry")
					inst := Instrument{
						Exchange:      getVal(row, "Exch", "EXCH", "Exchange", "exchange"),
						Token:         tok,
						Symbol:        getVal(row, "Symbol", "symbol"),
						TradingSymbol: getVal(row, "Trading Symbol", "TradingSymbol", "trading_symbol", "tradingSymbol"),
						Expiry:        expiry,
						LotSize:       getVal(row, "Lot Size", "LotSize", "lot_size"),
					}
					return inst, nil
				}
			}
			continue
		}

		// symbol-based match: match Symbol OR Trading Symbol (case-insensitive)
		sym := getVal(row, "Symbol", "symbol")
		trSym := getVal(row, "Trading Symbol", "TradingSymbol", "trading_symbol", "tradingSymbol")
		if strings.ToUpper(strings.TrimSpace(sym)) == symbolUpper || strings.ToUpper(strings.TrimSpace(trSym)) == symbolUpper {
			expiry := getVal(row, "Expiry Date", "expiry_date", "Expiry", "expiry")
			inst := Instrument{
				Exchange:      getVal(row, "Exch", "EXCH", "Exchange", "exchange"),
				Token:         getVal(row, "Token", "token"),
				Symbol:        sym,
				TradingSymbol: trSym,
				Expiry:        expiry,
				LotSize:       getVal(row, "Lot Size", "LotSize", "lot_size"),
			}
			return inst, nil
		}
	}

	// Not found
	return map[string]interface{}{"stat": "Not_ok", "emsg": "The symbol is not available in this exchange", "encKey": nil}, nil
}

// GetInstrumentForFNO fetches F&O instruments based on parameters.
// exchange: "NFO", "CDS", "MCX", "BFO", "BCD"
// symbol: trading symbol (e.g. "NIFTY")
// expiryDate: in "YYYY-MM-DD"
// isFut: true for futures, false for options
// strike: nil for futures or when you want all strikes; pointer to string otherwise
// isCE: true for CE, false for PE
// GetInstrumentForFNO: robust F&O lookup.
// Parameters:
//
//	exchange: "NFO", "MCX", etc.
//	symbol: underlying symbol like "NIFTY"
//	expiryDate: "YYYY-MM-DD" (optional — empty means nearest expiry)
//	isFut: true for futures, false for options
//	strike: pointer to strike string (optional; nil or "" means any strike for the expiry)
//	isCE: true for CE, false for PE (ignored for futures)
//
// Returns the same style as before (interface{}, error) for backward compatibility:
//   - on success: either a single tradesync.Instrument or []tradesync.Instrument
//   - on failure: map[string]interface{}{"stat":"Not_ok","emsg":...}
func (th *TradeHub) GetInstrumentForFNO(
	exchange string,
	symbol string,
	expiryDate string,
	isFut bool,
	strike *string,
	isCE bool,
) (interface{}, error) {

	exchange = strings.ToUpper(exchange)
	symbol = strings.ToUpper(symbol)

	rows, err := ContractRead(exchange)
	if err != nil || len(rows) == 0 {
		_, _ = th.GetContractMaster(exchange)
		rows, err = ContractRead(exchange)
		if err != nil {
			return map[string]interface{}{
				"stat": "Not_ok",
				"emsg": "Unable to read contract master",
			}, nil
		}
	}

	// ---------- Step 1: Collect all rows matching symbol ----------
	symbolRows := []map[string]string{}
	for _, r := range rows {
		if strings.EqualFold(r["Symbol"], symbol) ||
			strings.EqualFold(r["Trading Symbol"], symbol) ||
			strings.Contains(strings.ToUpper(r["Trading Symbol"]), symbol) {

			symbolRows = append(symbolRows, r)
		}
	}

	if len(symbolRows) == 0 {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": "No rows for symbol",
		}, nil
	}

	// ---------- Step 2: Try to match expiry EXACTLY ----------
	expiryMatched := []map[string]string{}
	for _, r := range symbolRows {
		if strings.TrimSpace(r["Expiry Date"]) == expiryDate {
			expiryMatched = append(expiryMatched, r)
		}
	}

	candidateRows := expiryMatched
	if len(candidateRows) == 0 {
		// If expiry not found → ignore expiry and continue
		candidateRows = symbolRows
	}

	// ---------- Step 3: Match by FUT/OPT & CE/PE ----------
	filtered := []map[string]string{}
	strikeVal := ""
	if strike != nil {
		strikeVal = strings.TrimSpace(*strike)
	}

	for _, r := range candidateRows {
		optType := strings.ToUpper(r["Option Type"])
		instType := strings.ToUpper(r["Instrument Type"])

		// FUTURE
		if isFut {
			if optType == "XX" || strings.Contains(instType, "FUT") {
				filtered = append(filtered, r)
			}
			continue
		}

		// OPTION CE/PE
		if optType == "" {
			continue
		}
		if isCE && optType != "CE" {
			continue
		}
		if !isCE && optType != "PE" {
			continue
		}

		// strike match
		if strikeVal != "" && r["Strike Price"] != strikeVal {
			continue
		}

		filtered = append(filtered, r)
	}

	if len(filtered) == 0 {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": "No matching FNO instrument",
		}, nil
	}

	// ---------- Step 4: Instrument struct ----------
	out := []Instrument{}
	uniq := map[string]bool{}
	for _, r := range filtered {
		tok := strings.TrimSpace(r["Token"])
		if tok == "" || uniq[tok] {
			continue
		}
		uniq[tok] = true

		out = append(out, Instrument{
			Exchange:      r["Exch"],
			Token:         tok,
			Symbol:        r["Symbol"],
			TradingSymbol: r["Trading Symbol"],
			Expiry:        r["Expiry Date"],
			LotSize:       r["Lot Size"],
		})
	}

	if len(out) == 1 {
		return out[0], nil
	}
	return out, nil
}

// Helper: getFirst tries multiple keys in row map and returns the first non-empty value
func getFirst(row map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := row[k]; ok && strings.TrimSpace(v) != "" {
			return v
		}
		// also try lowercase
		kl := strings.ToLower(k)
		if v, ok := row[kl]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Helper: numericStringEqual returns true if two numeric-looking strings equal numerically or as strings
func numericStringEqual(a, b string) bool {
	// direct compare
	if a == b {
		return true
	}
	af, aerr := strconv.ParseFloat(a, 64)
	bf, berr := strconv.ParseFloat(b, 64)
	if aerr == nil && berr == nil {
		return af == bf
	}
	return false
}

// ------------------------- Example Order Methods (Place/Modify/Cancel) -------------------------

func (th *TradeHub) PlaceOrder(instrumentId string, exchange string, transactionType string, quantity interface{},
	orderComplexity string, product string, orderType string, price interface{}, slTriggerPrice interface{},
	slLegPrice interface{}, targetLegPrice interface{}, validity string) (map[string]interface{}, error) {

	// Basic validation similar to validate_place_order
	v := Validator{}
	// check that mandatory fields are non-empty
	required := map[string]string{
		"Instrument Id":    instrumentId,
		"Exchange":         exchange,
		"Transaction Type": transactionType,
		"Quantity":         fmt.Sprintf("%v", quantity),
		"Order Complexity": orderComplexity,
		"Product":          product,
		"Order Type":       orderType,
		"Validity":         validity,
	}
	if orderType == "LIMIT" || orderType == "SL" {
		required["Price"] = fmt.Sprintf("%v", price)
	}
	if orderType == "SL" || orderType == "SLM" {
		required["SL Trigger Price"] = fmt.Sprintf("%v", slTriggerPrice)
	}
	// Validate
	for k, val := range required {
		if err := v.IsEmpty(val, k); err != nil {
			return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
		}
	}
	// Build data
	data := []map[string]interface{}{
		{
			"instrumentId":    instrumentId,
			"exchange":        exchange,
			"transactionType": transactionType,
			"quantity":        quantity,
			"orderComplexity": orderComplexity,
			"product":         product,
			"orderType":       orderType,
			"price":           price,
			"slTriggerPrice":  slTriggerPrice,
			"slLegPrice":      slLegPrice,
			"targetLegPrice":  targetLegPrice,
			"validity":        validity,
		},
	}
	resp, err := th.InitPost("ordExecute", data, nil, "")
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	return resp, nil
}

func (th *TradeHub) ModifyOrder(
	brokerOrderId string,
	price string,
	slTriggerPrice string,
	slLegPrice string,
	targetLegPrice string,
	quantity string,
	orderType string,
	trailingSLAmount string,
	validity string,
	disclosedQuantity string,
	marketProtectionPrecent string,
	orderComplexity string,
	deviceId string,
) (map[string]interface{}, error) {

	data := map[string]interface{}{
		"brokerOrderId":           brokerOrderId,
		"quantity":                quantity, // always string
		"orderType":               orderType,
		"slTriggerPrice":          slTriggerPrice,
		"price":                   price,
		"slLegPrice":              slLegPrice,
		"trailingSLAmount":        trailingSLAmount,
		"targetLegPrice":          targetLegPrice,
		"validity":                validity,
		"disclosedQuantity":       disclosedQuantity,
		"marketProtectionPrecent": marketProtectionPrecent,
		"deviceId": func() string {
			if marketProtectionPrecent != "" {
				return deviceId
			}
			return ""
		}(),
	}

	resp, err := th.InitPost("ordModify", data, nil, "")
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

func (th *TradeHub) CancelOrder(brokerOrderId string) (map[string]interface{}, error) {
	if strings.TrimSpace(brokerOrderId) == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "Broker Order Id is required", "encKey": nil}, nil
	}
	data := map[string]interface{}{"brokerOrderId": brokerOrderId}
	return th.InitPost("ordCancel", data, nil, "")
}

// data := [ { "brokerOrderId": brokerOrderId, "orderComplexity": orderComplexity } ]
func (th *TradeHub) ExitBracketOrder(brokerOrderId string, orderComplexity string) (map[string]interface{}, error) {
	// Normalize orderComplexity (if user passed enum values, they must be converted to string before calling)
	oc := strings.TrimSpace(orderComplexity)

	payload := []map[string]string{
		{
			"brokerOrderId":   brokerOrderId,
			"orderComplexity": oc,
		},
	}

	// Call InitPost with endpoint key per your InitPost signature
	resp, err := th.InitPost("ordExitBracket", payload, nil, "")
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error(), "encKey": nil}, nil
	}
	return resp, nil
}

// SingleOrderMargin accepts instrument as either tradesync.Instrument or a map and builds payload.
func (th *TradeHub) SingleOrderMargin(
	instrument interface{}, // can be Instrument or map[string]interface{}
	transactionType string,
	quantity string,
	orderComplexity string,
	product string,
	orderType string,
	price string,
	slTriggerPrice string,
	slLegPrice string,
) (map[string]interface{}, error) {

	// extract token and exchange from instrument
	var token, exchange string

	switch v := instrument.(type) {
	case Instrument:
		token = v.Token
		exchange = v.Exchange
	case *Instrument:
		token = v.Token
		exchange = v.Exchange
	case map[string]interface{}:
		if t, ok := v["Token"].(string); ok {
			token = t
		} else if t, ok := v["token"].(string); ok {
			token = t
		}
		if e, ok := v["Exchange"].(string); ok {
			exchange = e
		} else if e, ok := v["exch"].(string); ok {
			exchange = e
		}
	case map[string]string:
		if t, ok := v["Token"]; ok {
			token = t
		}
		if e, ok := v["Exchange"]; ok {
			exchange = e
		}
	default:
		// try reflection or fail
	}

	if strings.TrimSpace(exchange) == "" || strings.TrimSpace(token) == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "instrument must include Exchange and Token"}, nil
	}

	data := map[string]interface{}{
		"instrumentId":    token, // or "instrument" depending on API
		"exchange":        exchange,
		"transactionType": transactionType,
		"quantity":        quantity,
		"orderComplexity": orderComplexity,
		"product":         product,
		"orderType":       orderType,
		"price":           price,
		"slTriggerPrice":  slTriggerPrice,
		"slLegPrice":      slLegPrice,
	}

	// Call InitPost with proper endpoint key per your InitPost signature
	resp, err := th.InitPost("SingleOrdMargin", data, nil, "")
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error()}, nil
	}
	return resp, nil
}

// GetStringValue converts enums or interface{} to a string.
func GetStringValue(v interface{}) string {
	if v == nil {
		return ""
	}

	// Case 1: already a string
	if s, ok := v.(string); ok {
		return s
	}

	// Case 2: enum with String() method
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}

	// Case 3: map with ["value"]
	if m, ok := v.(map[string]interface{}); ok {
		if raw, exists := m["value"]; exists {
			if s2, ok2 := raw.(string); ok2 {
				return s2
			}
		}
	}

	// Case 4: fallback
	return fmt.Sprintf("%v", v)
}

func ExtractInstrument(inst interface{}) (token, exchange, tradingSymbol string, ok bool) {
	if inst == nil {
		return "", "", "", false
	}
	switch v := inst.(type) {
	case Instrument:
		return v.Token, v.Exchange, v.TradingSymbol, true
	case *Instrument:
		return v.Token, v.Exchange, v.TradingSymbol, true
	case map[string]interface{}:
		t, _ := v["Token"].(string)
		if t == "" {
			t, _ = v["token"].(string)
		}
		e, _ := v["Exchange"].(string)
		if e == "" {
			e, _ = v["Exch"].(string)
			e, _ = v["exchange"].(string)
		}
		ts, _ := v["Trading Symbol"].(string)
		if ts == "" {
			ts, _ = v["trading_symbol"].(string)
			ts, _ = v["tradingSymbol"].(string)
		}
		if t != "" && e != "" {
			return t, e, ts, true
		}
	case map[string]string:
		t := v["Token"]
		e := v["Exchange"]
		ts := v["Trading Symbol"]
		if t != "" && e != "" {
			return t, e, ts, true
		}
	}
	return "", "", "", false
}

// GTT_placeOrder — EXACT 1:1
func (th *TradeHub) GTT_placeOrder(
	transactionType interface{},
	quantity string,
	orderComplexity interface{},
	product interface{},
	orderType interface{},
	price string,
	gttValue string,
	validity interface{},
	instrument interface{}, // optional
	instrumentId string, // optional
	exchange interface{}, // optional
	tradingSymbol string, // optional
) (map[string]interface{}, error) {
	if instrument != nil {
		tok, exchVal, ts, ok := ExtractInstrument(instrument)
		if !ok {
			return map[string]interface{}{
				"stat": "Not_ok",
				"emsg": "Instrument must be of type Instrument or include Token and Exchange",
			}, nil
		}

		if exchange == nil || GetStringValue(exchange) == "" {
			exchange = exchVal
		}

		if instrumentId == "" {
			instrumentId = tok
		}

		if tradingSymbol == "" {
			tradingSymbol = ts
		}
	}

	// ------------------------------------------------------------
	// 2: getattr(x, 'value', x)
	// ------------------------------------------------------------
	tx := GetStringValue(transactionType)
	oc := GetStringValue(orderComplexity)
	prod := GetStringValue(product)
	ot := GetStringValue(orderType)
	val := GetStringValue(validity)
	exStr := GetStringValue(exchange)

	if tradingSymbol == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "tradingSymbol cannot be empty"}, nil
	}
	if quantity == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "quantity cannot be empty"}, nil
	}
	if price == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "price cannot be empty"}, nil
	}
	if gttValue == "" {
		return map[string]interface{}{"stat": "Not_ok", "emsg": "gttValue cannot be empty"}, nil
	}

	data := map[string]interface{}{
		"instrumentId":    instrumentId,
		"tradingSymbol":   tradingSymbol,
		"exchange":        exStr,
		"transactionType": tx,
		"quantity":        quantity,
		"orderComplexity": oc,
		"product":         prod,
		"orderType":       ot,
		"price":           price,
		"gttValue":        gttValue,
		"validity":        val,
	}

	resp, err := th.InitPost("ordGTT_Execute", data, nil, "")
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

func (th *TradeHub) GTT_modifyOrder(
	brokerOrderId string,
	instrument interface{}, // optional
	quantity string, // optional
	orderComplexity interface{}, // optional enum or string
	product interface{}, // optional enum or string
	orderType interface{}, // optional enum or string
	price string, // optional
	gttValue string, // optional
	validity interface{}, // optional enum or string
	exchange interface{}, // optional
	tradingSymbol string, // optional
) (map[string]interface{}, error) {

	if instrument != nil {
		tok, exchVal, ts, ok := ExtractInstrument(instrument)
		if !ok {
			return map[string]interface{}{
				"stat": "Not_ok",
				"emsg": "Instrument must be of type Instrument or include Token and Exchange",
			}, nil
		}

		// exchange = exchange or instrument.exchange
		if exchange == nil || GetStringValue(exchange) == "" {
			exchange = exchVal
		}

		// tradingSymbol = tradingSymbol or instrument.trading_symbol
		if tradingSymbol == "" {
			tradingSymbol = ts
		}

		// instrumentId always comes from instrument.token
		_ = tok
	}

	oc := GetStringValue(orderComplexity)
	prod := GetStringValue(product)
	ot := GetStringValue(orderType)
	val := GetStringValue(validity)
	exStr := GetStringValue(exchange)

	instToken := ""
	if instrument != nil {
		tok, _, _, ok := ExtractInstrument(instrument)
		if ok {
			instToken = tok
		}
	}

	data := map[string]interface{}{
		"brokerOrderId":   brokerOrderId,
		"instrumentId":    instToken,
		"tradingSymbol":   tradingSymbol,
		"exchange":        exStr,
		"quantity":        quantity,
		"orderComplexity": oc,
		"product":         prod,
		"orderType":       ot,
		"price":           price,
		"gttValue":        gttValue,
		"validity":        val,
	}

	resp, err := th.InitPost("ordGTT_Modify", data, nil, "")
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

// GTT_cancelOrder - exact conversion of GTT_cancelOrder
func (th *TradeHub) GTT_cancelOrder(brokerOrderId string) (map[string]interface{}, error) {
	// Validate brokerOrderId
	if strings.TrimSpace(brokerOrderId) == "" {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": "Order Number must be a non-empty string",
		}, nil
	}

	// Build payload
	data := map[string]interface{}{
		"brokerOrderId": brokerOrderId,
	}

	// Call endpoint
	resp, err := th.InitPost("ordGTT_Cancel", data, nil, "")
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

// GetOrderHistory - call endpoint key with brokerOrderId as path parameter (GET)
func (th *TradeHub) GetOrderHistory(brokerOrderId string) (map[string]interface{}, error) {
	if strings.TrimSpace(brokerOrderId) == "" {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": "Order Number must be a non-empty string",
		}, nil
	}

	data := map[string]interface{}{
		"brokerOrderId": brokerOrderId,
	}

	// Use the correct endpoint key (must exist in Endpoints map!)
	resp, err := th.InitPost("getOrdHistory", data, nil, "")
	if err != nil {
		return map[string]interface{}{
			"stat": "Not_ok",
			"emsg": err.Error(),
		}, nil
	}

	return resp, nil
}

// GetOrderHistoryPost - call endpoint using POST with JSON payload
func (th *TradeHub) GetOrderHistoryPost(brokerOrderId string) (map[string]interface{}, error) {
	endpointKey := "getOrderHistory"
	data := map[string]interface{}{"brokerOrderId": brokerOrderId}
	resp, err := th.InitPost(endpointKey, data, nil, "")
	if err != nil {
		return map[string]interface{}{"stat": "Not_ok", "emsg": err.Error()}, nil
	}
	return resp, nil
}
