# 🌐 AlynCoin Blockchain Explorer

## 🚀 Run Blockchain Explorer Backend (Docker)

```bash
cd ~/AlynCoin/src/explorer
docker build -t alyncoin-explorer .
docker run -p 8080:8080 alyncoin-explorer
