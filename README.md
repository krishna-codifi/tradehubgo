# 🚀 TradeSync Go Sample Project  
### A Complete Demo of REST + WebSocket Integration using `tradehubgo`

![Go Version](https://img.shields.io/badge/Go-1.20%2B-blue)
![Status](https://img.shields.io/badge/Status-Test-yellow)

This project provides a **full working demonstration** of how to integrate with the  
**TradeSync / TradeHub Go SDK** (`github.com/krishna-codifi/tradehubgo`).

It uses a realistic production-like structure and clearly commented code to make learning easy.

---

## 📁 Project Structure

```
project-root/
│
├── tradesync.go      # Core REST API wrapper (provided by SDK)
├── ws.go             # WebSocket implementation (provided by SDK)
│
└── cmd/
    └── main.go       # Full-feature usage example (REST + WebSocket)
```

---

## ✨ Features Demonstrated

| Category | Features |
|---------|----------|
| **Authentication** | Session generation, ENV + CLI credential handling |
| **User APIs** | Profile, Funds, Positions, Holdings |
| **Market Data** | Contract Master, Instrument search, F&O chain lookup |
| **Trading** | Place/Modify/Cancel Order, Square-Off, Exit Bracket |
| **Margin** | Single Order Margin calculator |
| **GTT** | Place, Modify, Cancel GTT orders |
| **Reports** | Orderbook, Tradebook, Order History |
| **WebSocket** | Connect, Subscribe to LTP, Handle feed, Reconnect logic |

All features are modular, toggle-based and explained with inline comments.

---

## 🚀 Getting Started

### 1️⃣ Install Go

Ensure Go **1.20 or later**:

```bash
go version
```

---

### 2️⃣ Clone the repository

```bash
git clone <your-repo-url>
cd <your-project>
```

---

### 3️⃣ Set your credentials

You can set credentials using **environment variables**:

```bash
export USER_ID="your_user_id"
export AUTH_CODE="your_auth_code"
export SECRET_KEY="your_secret_key"
export API_KEY="your_websocket_key"
```

Or pass them via **CLI flags**:

```bash
go run ./cmd/main.go   --user=XXXX   --auth=YYYY   --secret=ZZZZ   --apikey=AAAA
```

---

## ▶️ Running the Sample

### Run directly:

```bash
go run ./cmd/main.go
```

### Build a standalone binary:

```bash
go build -o tradesync-sample ./cmd/main.go
./tradesync-sample
```

---

## 🎛 Available CLI Flags

### General

```
--user              User ID
--auth              Auth code
--secret            Secret key
--apikey            WebSocket API key
--all               Enable all features
```

### REST Toggles

```
--get-profile
--get-funds
--get-positions
--get-holdings
--get-cm
--scripts
--place-order
--modify-order
--cancel-order
--position-sqroff
--exit-bracket
--single-order-margin
--gtt-place
--gtt-modify
--gtt-cancel
--get-orderbook
--get-tradebook
--get-orderhistory
```

Example: run only profile + funds:

```bash
go run ./cmd/main.go --get-profile --get-funds
```

Run everything:

```bash
go run ./cmd/main.go --all
```

---

## 📂 Output Storage

All API responses are automatically saved in:

```
static/<DDMMYYYY>/ID-<USER_ID>/
```

Example files:

- `Session_<USERID>.json`
- `Funds_<USERID>.json`
- `OrderHistory_<USERID>.json`
- `GTT_placeOrder_<USERID>.json`

This makes debugging extremely easy.

---

## 🌐 WebSocket Workflow Overview

The WebSocket example in `main.go` demonstrates:

1. Generate session for WS  
2. Connect to TradeSync WebSocket  
3. Handle connection acknowledgement (`t = "ck"`)  
4. Subscribe to token:  
   ```
   Exchange: INDICES  
   Token:    26000  
   ```
5. Print real-time LTP feed  
6. Stop WebSocket  
7. Reconnect again  
8. Keep alive until user presses **Ctrl+C**

The feed handler prints:

```json
{
  "t": "sf",
  "lp": 22550.30,
  "tk": "26000"
}
```

---

## 🧠 Code Overview

### Utility Helpers

- `writeJSONToFile()` → Pretty-print JSON to file  
- `saveResult()` → Wrapper for consistent storage  
- `pretty()` → Debug JSON printing  

### Main Flow (REST)

- Load credentials  
- Create storage path  
- Authenticate  
- Run all enabled toggles  
- Each block prints results + saves output  

### Main Flow (WebSocket)

- Set credentials  
- Create session  
- Open WebSocket  
- Subscribe to instruments  
- Receive LTP updates  
- Clean disconnect and reconnect  

---

