# Risk Auditor

Token approval security scanner for EVM chains with x402 micropayments.

## API

### GET /approval-audit

Scans wallet for risky token approvals across 7 EVM chains.

**Query:**
- `wallet`: Ethereum address (required)
- `chains`: ethereum,polygon,base,arbitrum,optimism,bsc,avalanche (optional)

**Response:**
```json
{
  "approvals": [{
    "token_symbol": "USDC",
    "spender_address": "0x...",
    "allowance": "0xfff...",
    "is_unlimited": true
  }],
  "risk_flags": {...},
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

## Payment

0.001 SOL per request. Include Solana transaction signature in `X-PAYMENT` header (base64 JSON).

Wallet: `CE4BW1g1vuaS8hRQAGEABPi5PCuKBfJUporJxmdinCsY`

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
