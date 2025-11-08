![header](https://github.com/user-attachments/assets/6ad065ce-a087-488e-bf2a-101059a911b0)

# KAMIYO リスクオーディター | Risk Auditor

Token approval security scanner for EVM chains with x402 micropayments on Solana.

## Features

- Scans token approvals across 7 EVM chains via blockchain explorer APIs
- Detects unlimited approvals (MAX_UINT256), stale approvals (6+ months), exploited protocols
- Generates ERC20 revocation transactions
- Cross-references KAMIYO exploit database for protocol risk assessment

## API

### GET /approval-audit

Scans wallet for risky token approvals.

**Query:**
- `wallet`: Ethereum address (required)
- `chains`: ethereum,polygon,base,arbitrum,optimism,bsc,avalanche (optional, default: ethereum)

**Response:**
```json
{
  "approvals": [{
    "token_symbol": "USDC",
    "spender_address": "0x...",
    "allowance": "0xfff...",
    "is_unlimited": true
  }],
  "risk_flags": {
    "0x...-0x...": [{
      "type": "unlimited",
      "severity": "high",
      "description": "..."
    }]
  },
  "revoke_tx_data": [{
    "to": "0x...",
    "data": "0x095ea7b3...",
    "chainId": 1
  }]
}
```

### GET /exploits

Recent protocol exploits. Params: `protocol`, `chain`, `limit`.

### GET /risk-score/:protocol

Protocol risk score (0-100). Param: `chain`.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Risk Auditor API                         │
│                    (Express.js + x402 Payments)                 │
└────────────┬────────────────────────────────────┬───────────────┘
             │                                    │
     ┌───────▼─────────┐                 ┌────────▼────────┐
     │  /approval-audit│                 │ /risk-score     │
     │    Endpoint     │                 │  /exploits      │
     └───────┬─────────┘                 └────────┬────────┘
             │                                    │
    ┌────────▼──────────────────────────┐        │
    │   ApprovalsRouteHandler           │        │
    │   ┌───────────────────────────┐   │        │
    │   │ 1. Scan Approvals         │   │        │
    │   │ 2. Detect Risks           │   │        │
    │   │ 3. Generate Revocations   │   │        │
    │   └───────────────────────────┘   │        │
    └─┬─────────┬──────────┬────────────┘        │
      │         │          │                      │
┌─────▼─────┐ ┌▼──────────▼───┐     ┌───────────▼──────────┐
│ Approval  │ │ RiskDetector  │     │    DataService       │
│  Scanner  │ │               │     │  (Exploit Database)  │
└─────┬─────┘ └───────┬───────┘     └──────────┬───────────┘
      │               │                        │
      │      ┌────────▼────────┐               │
      │      │ Exploit History │◄──────────────┘
      │      │   Cross-Ref     │
      │      └─────────────────┘
      │
┌─────▼─────────────────────────────────────────────────┐
│            Blockchain Explorer APIs                   │
│  Etherscan │ Polygonscan │ Arbiscan │ Basescan │ ... │
└───────────────────────────────────────────────────────┘
```

### Data Flow

```
User Request
    │
    ├─► wallet: 0x742d35...
    ├─► chains: [ethereum, polygon]
    └─► x402: payment signature
         │
         ▼
    ┌─────────────────┐
    │ ApprovalScanner │
    └────────┬────────┘
             │
    ┌────────▼──────────────────────────────┐
    │  1. Fetch approval events             │
    │  2. Query current allowances          │
    │  3. Filter active approvals           │
    └────────┬──────────────────────────────┘
             │
             ▼
      ┌───────────────┐
      │ RiskDetector  │
      └───────┬───────┘
              │
    ┌─────────┼─────────┐
    │         │         │
 Unlimited  Stale  Exploited
 Approval   (6mo)  Protocol
    │         │         │
    └─────────┼─────────┘
              │
    ┌─────────▼──────────┐
    │ TransactionGenerator│
    │ approve(addr, 0)    │
    └─────────┬───────────┘
              │
     Revocation TX Data
```

### Payment Flow

```
┌──────────┐                                    ┌────────────────┐
│  Client  │                                    │  Risk Auditor  │
└─────┬────┘                                    └────────┬───────┘
      │                                                  │
      │  1. Create Solana transfer (0.001 SOL)          │
      │ ────────────────────────────────────────────►   │
      │                                                  │
      │  2. Get transaction signature                   │
      │ ◄────────────────────────────────────────────   │
      │                                                  │
      │  3. API Request with X-PAYMENT header           │
      │     X-PAYMENT: base64({                         │
      │       x402Version: 1,                            │
      │       payload: {                                 │
      │         signature: "5KW...",                     │
      │         amount: "1000000",                       │
      │         recipient: "CE4BW..."                    │
      │       }                                          │
      │     })                                           │
      │ ────────────────────────────────────────────►   │
      │                                         ┌────────▼────────┐
      │                                         │ x402Middleware  │
      │                                         │  1. Parse       │
      │                                         │  2. Verify sig  │
      │                                         │  3. Check cache │
      │                                         └────────┬────────┘
      │                                                  │
      │  4. Response with approval data                 │
      │ ◄────────────────────────────────────────────   │
      │                                                  │
      │  5. Additional requests (1h cache)              │
      │ ────────────────────────────────────────────►   │
      │ ◄────────────────────────────────────────────   │
```

## Payment

0.001 SOL per request. Include Solana transaction signature in `X-PAYMENT` header (base64 JSON).

Wallet: `CE4BW1g1vuaS8hRQAGEABPi5PCuKBfJUporJxmdinCsY`

Payment signature cached for 1 hour (multiple requests per transaction).

## x402scan Discovery

Risk Auditor is discoverable on [x402scan.com](https://www.x402scan.com) - the x402 ecosystem explorer.

**Live Endpoint:** https://risk-auditor.kamiyo.ai

The service implements the x402 discovery protocol via `/.well-known/x402`, exposing three resources:

1. **Approval Audit** - Scan wallet token approvals for security risks
2. **Exploit Intelligence** - Query 20+ sources for DeFi exploit data
3. **Risk Scoring** - Calculate protocol risk based on exploit history

All endpoints accept x402 payments (0.001 SOL per request) and return structured JSON with security intelligence.

To register on x402scan:
1. Visit https://www.x402scan.com/resources/register
2. Submit URL: `https://risk-auditor.kamiyo.ai`
3. The registry auto-validates the x402 schema

## Development

```bash
npm install
npm run dev  # port 3000
```

## Production

```bash
npm run build
npm start
```

Set API keys: `ETHERSCAN_API_KEY`, `POLYGONSCAN_API_KEY`, `BSCSCAN_API_KEY`, `ARBISCAN_API_KEY`, `OPTIMISTIC_ETHERSCAN_API_KEY`, `BASESCAN_API_KEY`, `SNOWTRACE_API_KEY`

## License

MIT
