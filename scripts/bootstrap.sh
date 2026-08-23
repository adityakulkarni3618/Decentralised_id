#!/usr/bin/env bash
# Convenience bootstrap: deploys contracts and seeds the database against an
# already-running `docker-compose up` stack. Run from the project root:
#   ./scripts/bootstrap.sh
set -euo pipefail

echo "==> Deploying smart contracts to the local Hardhat node..."
docker-compose exec -T hardhat-node npx hardhat run scripts/deploy.js --network localhost

echo ""
echo "==> Copy printed contract addresses into your .env, then restart backend:"
echo "    CREDENTIAL_REGISTRY_ADDRESS, REVOCATION_REGISTRY_ADDRESS, ISSUER_REGISTRY_ADDRESS"
echo "    docker-compose restart backend"

echo "==> Seeding MongoDB with demo accounts and credentials..."
docker-compose exec -T backend python -m scripts.seed_db --force

echo ""
echo "==> Done. Visit http://localhost:3000"
