# 🌐 AlynCoin Blockchain Explorer

## 🚀 Run Blockchain Explorer Backend (Docker)

```bash
cd ~/AlynCoin/src/explorer
docker build -t alyncoin-explorer .
docker run -p 8080:8080 alyncoin-explorer
```

The explorer exposes a simple REST API on port `8080`.

### Sample Endpoints

* `/api/status` – latest block height and node version
* `/api/block/<height>` – block details
* `/api/address/<addr>` – balance and transactions
* `/api/supply` – circulating and total supply
