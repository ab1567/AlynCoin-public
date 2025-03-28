#!/bin/bash

# CLI Helper to finalize a Governance DAO Proposal

API_URL="http://localhost:8080/api"

if [ -z "$1" ]; then
  echo "Usage: $0 <proposal_id>"
  exit 1
fi

PROPOSAL_ID=$1

echo "Fetching status for proposal ID: $PROPOSAL_ID..."

STATUS_JSON=$(curl -s ${API_URL}/proposal/status/${PROPOSAL_ID})
STATUS=$(echo "$STATUS_JSON" | jq -r '.status')

echo "Current Status: $STATUS"

if [ "$STATUS" != "Pending" ]; then
  echo "Proposal is not pending, no action needed."
  exit 0
fi

echo "Manually finalizing proposal..."
echo "Choose outcome:"
echo "1) Approve"
echo "2) Reject"
read -p "Enter choice (1 or 2): " choice

case $choice in
  1)
    FINAL_STATUS="APPROVED"
    ;;
  2)
    FINAL_STATUS="REJECTED"
    ;;
  *)
    echo "Invalid choice."
    exit 1
    ;;
esac

# Finalize via CLI (simulate update directly to DB or call internal logic)
# For now, we'll log it:
echo "Finalizing proposal '$PROPOSAL_ID' as $FINAL_STATUS..."

# You may extend this to directly interact with RocksDB or invoke internal C++ method.
echo "$PROPOSAL_ID finalized as $FINAL_STATUS" >> finalized_proposals.log

echo "Done. Logged to finalized_proposals.log."
