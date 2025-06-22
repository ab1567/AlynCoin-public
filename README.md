# AlynCoin
Privacy-focused cryptocurrency based on PoW

## Build and Run

Generate RSA keys locally before building or running the software. The keys are not tracked in version control.

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/System_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in keys/System_private.pem -pubout -out keys/System_public.pem
```
