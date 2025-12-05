// cmd/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	tradesync "github.com/krishna-codifi/tradehubgo"
)

// writeJSONToFile pretty-prints data to a JSON file (data may be any value).
func writeJSONToFile(path string, data interface{}) error {
	// If data is already a map[string]interface{} or struct, json.MarshalIndent will work.
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		// fallback: try to marshal a simple representation
		s := fmt.Sprintf("%#v", data)
		return os.WriteFile(path, []byte(s), 0644)
	}
	return os.WriteFile(path, b, 0644)
}

// saveResult saves `data` into storage dir with filename.
func saveResult(storageDir, filename string, data interface{}) {
	dest := filepath.Join(storageDir, filename)
	if err := writeJSONToFile(dest, data); err != nil {
		fmt.Printf("Failed to write file %s : %v\n", dest, err)
	} else {
		fmt.Printf("Saved: %s\n", dest)
	}
}

func pretty(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func main() {
	// Credentials (CLI or ENV)
	userFlag := flag.String("user", "", "User ID (or set USER_ID env)")
	authFlag := flag.String("auth", "", "Auth code (or set AUTH_CODE env)")
	secretFlag := flag.String("secret", "", "Secret key (or set SECRET_KEY env)")
	apiKeyFlag := flag.String("apikey", "", "API Key for Websocket (or set API_KEY env)")

	// Action toggles
	allFlag := flag.Bool("all", false, "Enable all actions")
	getCM := flag.Bool("get-cm", false, "Get contract master files")
	scriptsFlag := flag.Bool("scripts", false, "Perform script searches (instrument and F&O)")
	getProfile := flag.Bool("get-profile", false, "Get profile")
	getFunds := flag.Bool("get-funds", false, "Get funds")
	getPositions := flag.Bool("get-positions", false, "Get positions")
	getHoldings := flag.Bool("get-holdings", false, "Get holdings")

	placeOrder := flag.Bool("place-order", false, "Place order example")
	modifyOrder := flag.Bool("modify-order", false, "Modify order example")
	cancelOrder := flag.Bool("cancel-order", false, "Cancel order example")
	positionSqrOff := flag.Bool("position-sqroff", false, "Position square off example")
	exitBracket := flag.Bool("exit-bracket", false, "Exit bracket order example")
	singleOrderMargin := flag.Bool("single-order-margin", false, "Single order margin example")

	gttPlace := flag.Bool("gtt-place", false, "GTT place example")
	gttModify := flag.Bool("gtt-modify", false, "GTT modify example")
	gttCancel := flag.Bool("gtt-cancel", false, "GTT cancel example")

	getOrderbook := flag.Bool("get-orderbook", false, "Get orderbook")
	getTradebook := flag.Bool("get-tradebook", false, "Get tradebook")
	getOrderHistory := flag.Bool("get-orderhistory", false, "Get order history")

	flag.Parse()

	// If --all, enable all toggles
	if *allFlag {
		*getCM = true
		*scriptsFlag = true
		*getProfile = true
		*getFunds = true
		*getPositions = true
		*getHoldings = true
		*placeOrder = true
		*modifyOrder = true
		*cancelOrder = true
		*positionSqrOff = true
		*exitBracket = true
		*singleOrderMargin = true
		*gttPlace = true
		*gttModify = true
		*gttCancel = true
		*getOrderbook = true
		*getTradebook = true
		*getOrderHistory = true
	}

	// Credentials precedence: CLI flags override env
	userID := *userFlag
	if userID == "" {
		userID = os.Getenv("USER_ID")
	}
	authCode := *authFlag
	if authCode == "" {
		authCode = os.Getenv("AUTH_CODE")
	}
	secretKey := *secretFlag
	if secretKey == "" {
		secretKey = os.Getenv("SECRET_KEY")
	}

	apiKey := *apiKeyFlag
	if apiKey == "" {
		apiKey = os.Getenv("API_KEY")
	}

	// ** For testing purposes, you can hardcode credentials here:
	// userID = ""
	// authCode = ""
	// secretKey = ""
	// apiKey = "" // Websocket API Key

	if userID == "" || authCode == "" || secretKey == "" || apiKey == "" {
		fmt.Println("Warning: USER_ID/AUTH_CODE/SECRET_KEY/API_KEY not fully provided. Session requests may fail.")
	}

	// Storage path definition
	currDate := time.Now().Format("02012006")
	cwd, _ := os.Getwd()
	storage := filepath.Join(cwd, "static", currDate, "ID-"+userID)
	_ = os.MkdirAll(storage, 0755)

	storageDir := filepath.Join(cwd, "static", currDate, fmt.Sprintf("ID-%s", userID))
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		fmt.Println("Failed to create storage dir:", err)
		return
	}

	// Instantiate TradeHub from parent package
	trade := tradesync.NewTradeHub(userID, authCode, secretKey, "")

	// 1) Get session (always helpful to call first if toggles require session)
	fmt.Println("1. Get Session...")
	sessionResp, err := trade.GetSessionID("", "")
	if err != nil {
		fmt.Println("Get Session ID error:", err)
	} else {
		fmt.Printf("Session: %+v\n\n\n", sessionResp)
		saveResult(storageDir, fmt.Sprintf("Session_%s.json", userID), sessionResp)
	}

	// 2) Get Contract Master files
	if *getCM {
		fmt.Println("2. Get CM...")
		exchanges := []string{"NSE", "NFO", "CDS", "BSE", "BFO", "MCX", "INDICES"}
		for _, exch := range exchanges {
			res, err := trade.GetContractMaster(exch)
			if err != nil {
				fmt.Printf("GetContractMaster(%s) error: %v\n", exch, err)
				continue
			}
			fmt.Printf("GetContractMaster(%s): %+v\n", exch, res)
		}
	}

	// 3) Scripts / Instruments (including F&O)
	if *scriptsFlag {
		fmt.Println("3. Running scripts & F&O search...")

		// Fetch instrument by symbol (YESBANK) on NSE
		inst1, err := trade.GetInstrument("NSE", "YESBANK", "")
		if err != nil {
			fmt.Println("Error fetching YESBANK:", err)
		} else {
			fmt.Println("Instrument YESBANK NSE:", inst1)
		}
		fmt.Println("")

		// Fetch instrument by token (200306) on BSE
		inst2, err := trade.GetInstrument("BSE", "", "200306")
		if err != nil {
			fmt.Println("Error fetching token 200306:", err)
		} else {
			fmt.Println("Instrument token 200306 BSE:", inst2)
		}
		fmt.Println("")

		strike := "30000"
		instr, _ := trade.GetInstrumentForFNO("NFO", "NIFTY", "2026-06-25", false, &strike, false)
		fmt.Println(instr)
	}

	// 4) Profile
	if *getProfile {
		fmt.Println("4. Get Profile...")
		prof, err := trade.InitGet("getProfile", nil, "")
		if err != nil {
			fmt.Println("get_profile error:", err)
		} else {
			fmt.Printf("Profile: %+v\n", prof)
			saveResult(storageDir, fmt.Sprintf("Profile_%s.json", userID), prof)
		}
	}

	// 5) Get Funds
	if *getFunds {
		fmt.Println("5. Get Funds...")
		funds, err := trade.InitGet("getFunds", nil, "")
		if err != nil {
			fmt.Println("get_funds error:", err)
		} else {
			fmt.Printf("Funds: %+v\n", funds)
			saveResult(storageDir, fmt.Sprintf("Funds_%s.json", userID), funds)
		}
	}

	// 6) Get Positions
	if *getPositions {
		fmt.Println("6. Get Positions...")
		pos, err := trade.InitGet("getPositions", nil, "")
		if err != nil {
			fmt.Println("get_positions error:", err)
		} else {
			fmt.Printf("Positions: %+v\n", pos)
			saveResult(storageDir, fmt.Sprintf("Positions_%s.json", userID), pos)
		}
	}

	// 7) Get Holdings
	if *getHoldings {
		fmt.Println("7. Get Holdings...")
		holdings, _ := trade.GetHoldings("CNC")
		fmt.Println("Holdings:", holdings)
	}

	// 8) Place Order
	if *placeOrder {
		fmt.Println("8. Place Order...")
		// get instrument first (example token)
		instRaw, err := trade.GetInstrument("NSE", "", "14366")
		if err != nil {
			fmt.Println("GetInstrument for placeOrder error:", err)
		} else {
			// extract token
			instrumentId := ""
			switch v := instRaw.(type) {
			case tradesync.Instrument:
				instrumentId = v.Token
			case map[string]interface{}:
				if t, ok := v["Token"].(string); ok {
					instrumentId = t
				}
			}
			resp, err := trade.PlaceOrder(instrumentId, "NSE", "Buy", "2", "AMO", "Longterm", "Limit", "6.2", "0", "0", "0", "DAY")
			if err != nil {
				fmt.Println("PlaceOrder error:", err)
			} else {
				fmt.Printf("PlaceOrder response: %+v\n", resp)
				saveResult(storageDir, fmt.Sprintf("placeOrder_%s.json", userID), resp)
			}
		}
	}

	// 9) Modify Order
	if *modifyOrder {
		fmt.Println("9. Modify Order...")

		brokerOrderId := "25120400195331"
		price := "6.5"
		slTriggerPrice := "0"
		slLegPrice := ""
		targetLegPrice := ""
		quantity := "5"
		orderType := tradesync.OrderTypeLimit.String()
		trailingSLAmount := ""
		validity := tradesync.PositionDay.String()
		disclosedQuantity := ""
		marketProtectionPrecent := ""
		orderComplexity := ""
		deviceId := "180a894d3ce7be4349c4139bd13377f5"

		resp, err := trade.ModifyOrder(
			brokerOrderId,
			price,
			slTriggerPrice,
			slLegPrice,
			targetLegPrice,
			quantity,
			orderType,
			trailingSLAmount,
			validity,
			disclosedQuantity,
			marketProtectionPrecent,
			orderComplexity,
			deviceId,
		)

		if err != nil {
			fmt.Println("ModifyOrder error:", err)
		} else {
			fmt.Println("ModifyOrder response:", resp)
			modifyPath := filepath.Join(storage, fmt.Sprintf("modifyOrder_%s.json", userID))
			if err := writeJSONToFile(modifyPath, resp); err != nil {
				fmt.Println("Failed to write modifyOrder file:", err)
			}
		}
	}

	// 10) Cancel Order
	if *cancelOrder {
		fmt.Println("10. Cancel Order...")
		resp, err := trade.CancelOrder("25120400113863")
		if err != nil {
			fmt.Println("CancelOrder error:", err)
		} else {
			fmt.Printf("CancelOrder response: %+v\n", resp)
			saveResult(storageDir, fmt.Sprintf("CancelOrder_%s.json", userID), resp)
		}
	}

	// 11) Position Square Off
	if *positionSqrOff {
		fmt.Println("11. Position Square Off...")
		instRaw, err := trade.GetInstrument(tradesync.ExchangeNSE.String(), "", "14366")
		if err != nil {
			fmt.Println("GetInstrument error:", err)
		} else {
			instrumentId := ""
			switch v := instRaw.(type) {
			case tradesync.Instrument:
				instrumentId = v.Token
			case map[string]interface{}:
				if t, ok := v["Token"].(string); ok {
					instrumentId = t
				}
			}
			resp, err := trade.PlaceOrder(instrumentId, tradesync.ExchangeNSE.String(), tradesync.TransactionSell.String(), "1", tradesync.OrderComplexityRegular.String(), tradesync.ProductIntraday.String(), tradesync.OrderTypeMarket.String(), "0", "0", "0", "0", tradesync.PositionDay.String())
			//resp, err := trade.PlaceOrder(instrumentId, tradesync.ExchangeNSE.String(), tradesync.TransactionSell.String() "Sell", "1", "Regular", "Intraday", "Market", "0", "0", "0", "0", "DAY")
			if err != nil {
				fmt.Println("PositionSqrOff error:", err)
			} else {
				fmt.Printf("PositionSqrOff response: %+v\n", resp)
				saveResult(storageDir, fmt.Sprintf("positionSqrOff_%s.json", userID), resp)
			}
		}
	}

	// 12) Exit Bracket Order
	if *exitBracket {
		fmt.Println("12. Exit Bracket Order...")
		brokerOrderId := "250424000007880"
		orderComplexity := tradesync.OrderComplexityCover.String()

		// Optional: print the payload you will send for debugging
		payload := []map[string]string{
			{
				"brokerOrderId":   brokerOrderId,
				"orderComplexity": orderComplexity,
			},
		}
		fmt.Printf("ExitBracketOrder payload: %+v\n", payload)

		// Call the method
		resp, err := trade.ExitBracketOrder(brokerOrderId, orderComplexity)
		if err != nil {
			fmt.Println("ExitBracketOrder error:", err)
		} else {
			fmt.Println("ExitBracketOrder response:", resp)
			saveResult(storage, fmt.Sprintf("exitBracketOrder_%s.json", userID), resp)
		}
	}

	// 13) Single Order Margin
	if *singleOrderMargin {
		fmt.Println("13. Single Order Margin...")

		// Get instrument (returns tradesync.Instrument or map[string]interface{})
		instRaw, err := trade.GetInstrument("NSE", "HFCL", "")
		if err != nil {
			fmt.Println("GetInstrument HFCL error:", err)
		} else {
			transactionType := tradesync.TransactionBuy.String() // "BUY"
			quantity := "1"
			orderComplexity := tradesync.OrderComplexityRegular.String() // "REGULAR"
			product := tradesync.ProductIntraday.String()                // "INTRADAY"
			orderType := tradesync.OrderTypeMarket.String()              // "MARKET"
			price := "82.99"
			slTriggerPrice := "1215"
			slLegPrice := "0"

			// Call the Go method with the instrument object as first argument
			resp, err := trade.SingleOrderMargin(
				instRaw,
				transactionType,
				quantity,
				orderComplexity,
				product,
				orderType,
				price,
				slTriggerPrice,
				slLegPrice,
			)
			if err != nil {
				fmt.Println("SingleOrderMargin error:", err)
			} else {
				fmt.Println("User Single Order Margin :", resp)
				saveResult(storage, fmt.Sprintf("Single_Order_Margin_%s.json", userID), resp)
			}
		}
	}

	// 14) GTT Place / Modify / Cancel examples
	if *gttPlace {
		fmt.Println("14. GTT Place Order...")

		inst, _ := trade.GetInstrument("NFO", "", "35167")

		resp, err := trade.GTT_placeOrder(
			tradesync.TransactionSell,        // transactionType
			"3100",                           // quantity
			tradesync.OrderComplexityRegular, // orderComplexity
			tradesync.ProductIntraday,        // product
			tradesync.OrderTypeLimit,         // orderType
			"100",                            // price
			"10",                             // gttValue
			tradesync.PositionDay,            // validity
			inst,                             // instrument
			"",                               // instrumentId
			nil,                              // exchange
			"",                               // tradingSymbol
		)

		if err != nil {
			fmt.Println("GTT_placeOrder error:", err)
		} else {
			fmt.Println("User GTT_placeOrder:", resp)
			saveResult(storage, fmt.Sprintf("GTT_placeOrder_%s.json", userID), resp)
		}
	}

	// 14. GTT Modify
	if *gttModify {
		fmt.Println("14. GTT Modify Order...")

		brokerOrderId := "25120400001270"
		inst, _ := trade.GetInstrument(tradesync.ExchangeNFO.String(), "", "35167")

		resp, err := trade.GTT_modifyOrder(
			brokerOrderId,                    // brokerOrderId
			inst,                             // instrument
			"3100",                           // quantity
			tradesync.OrderComplexityRegular, // orderComplexity
			tradesync.ProductIntraday,        // product
			tradesync.OrderTypeLimit,         // orderType
			"100",                            // price
			"10",                             // gttValue
			tradesync.PositionDay,            // validity
			nil,                              // exchange
			"",                               // tradingSymbol
		)

		if err != nil {
			fmt.Println("GTT_modifyOrder error:", err)
		} else {
			fmt.Println("GTT_modify response:", resp)
			saveResult(storage, fmt.Sprintf("GTT_modify_%s.json", userID), resp)
		}
	}

	// 15. GTT Cancel
	if *gttCancel {
		fmt.Println("15. GTT Cancel Order...")

		brokerOrderId := "25120400001270"

		resp, err := trade.GTT_cancelOrder(brokerOrderId)
		if err != nil {
			fmt.Println("GTT_cancelOrder error:", err)
		} else {
			fmt.Println("User GTT Cancel Order :", resp)
			saveResult(storage, fmt.Sprintf("GTT_cancelOrder_%s.json", userID), resp)
		}
	}

	// 15) Orderbook
	if *getOrderbook {
		fmt.Println("15. Get Orderbook...")
		resp, err := trade.InitGet("getOrderbook", nil, "")
		if err != nil {
			fmt.Println("get_orderbook error:", err)
		} else {
			fmt.Printf("Orderbook: %+v\n", resp)
			saveResult(storageDir, fmt.Sprintf("Orderbook_%s.json", userID), resp)
		}
	}

	// 16) Tradebook
	if *getTradebook {
		fmt.Println("16. Get Tradebook...")
		resp, err := trade.InitGet("getTradebook", nil, "")
		if err != nil {
			fmt.Println("get_tradebook error:", err)
		} else {
			fmt.Printf("Tradebook: %+v\n", resp)
			saveResult(storageDir, fmt.Sprintf("Tradebook_%s.json", userID), resp)
		}
	}

	// 17) Order History
	if *getOrderHistory {
		fmt.Println("17. Get Order History...")
		orderHistory, err := trade.GetOrderHistory("25120400113863")
		if err != nil {
			fmt.Println("GetOrderHistory error:", err)
		} else {
			fmt.Println("OrderHistory:", orderHistory)
			saveResult(storage, fmt.Sprintf("OrderHistory_%s.json", userID), orderHistory)
		}
	}

	// -------------------------
	// Websocket flow (LTP subscription)
	// -------------------------
	fmt.Println("\n--- Websocket flow ---")
	var LTP float64
	socketOpen := make(chan struct{})
	subscribeFlag := false
	var subscribeList []tradesync.InstrumentWS

	client := tradesync.SetCredentials(userID, apiKey)
	// Get session ID
	fmt.Println("Get Session ID for Websocket...")
	resp, err := client.GetSessionID()
	if err != nil {
		fmt.Println("GetSessionID error:", err)
		pretty(resp)
		return
	}
	pretty(resp)

	socketOpenCb := func() {
		fmt.Println("Connected")
		// signal that socket is open
		select {
		case <-socketOpen:
			// already signaled
		default:
			close(socketOpen)
		}
		if subscribeFlag && len(subscribeList) > 0 {
			if err := client.Subscribe(subscribeList); err != nil {
				fmt.Println("subscribe error:", err)
			}
		}
	}

	socketCloseCb := func() {
		fmt.Println("Closed")
		LTP = 0
	}

	socketErrorCb := func(err error) {
		fmt.Println("Error :", err)
		LTP = 0
	}

	feedDataCb := func(msg []byte) {
		var fm map[string]interface{}
		if err := json.Unmarshal(msg, &fm); err != nil {
			// Not a map - print raw
			fmt.Println("Feed (raw):", string(msg))
			return
		}
		if t, ok := fm["t"].(string); ok && t == "ck" {
			fmt.Printf("Connection Acknowledgement status :%v (Websocket Connected)\n", fm["s"])
			subscribeFlag = true
			fmt.Println("subscribe_flag :", subscribeFlag)
			return
		}
		if t, ok := fm["t"].(string); ok && t == "tk" {
			fmt.Println("Token Acknowledgement status :", fm)
			return
		}
		fmt.Println("Feed :", fm)
		if lp, ok := fm["lp"]; ok {
			switch v := lp.(type) {
			case float64:
				LTP = v
			case int:
				LTP = float64(v)
			case string:
				// string parse
			}

			fmt.Println("Current LTP:", LTP)
		}
	}

	// attach callbacks
	client.OnOpen = socketOpenCb
	client.OnClose = socketCloseCb
	client.OnError = socketErrorCb
	client.SubscribeHandler = func(msg []byte) {
		feedDataCb(msg)
	}

	// start websocket in background
	if err := client.StartWebsocket(true, false); err != nil {
		fmt.Println("StartWebsocket error:", err)
	} else {
		// wait until open
		select {
		case <-socketOpen:
			fmt.Println("socket opened")
		case <-time.After(10 * time.Second):
			fmt.Println("socket open timeout")
		}
	}

	// subscribe to INDICES token 26000
	instIdx, err := client.GetInstrumentByTokenWS("INDICES", "26000")
	if err != nil {
		fmt.Println("GetInstrumentByToken error:", err)
	} else {
		subscribeList = []tradesync.InstrumentWS{instIdx}
		if err := client.Subscribe(subscribeList); err != nil {
			fmt.Println("Subscribe error:", err)
		} else {
			fmt.Println("Subscribed to INDICES 26000: ", subscribeList)
		}
	}

	fmt.Println(time.Now())
	time.Sleep(10 * time.Second)
	fmt.Println(time.Now())

	// stop websocket
	client.StopWebsocket()
	time.Sleep(10 * time.Second)
	fmt.Println(time.Now())

	// reconnect websocket
	if err := client.StartWebsocket(true, false); err != nil {
		fmt.Println("StartWebsocket (reconnect) error:", err)
	}

	// keep program until Ctrl+C
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	fmt.Println("exiting")
}
