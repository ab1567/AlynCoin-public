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

echo "Finalizing proposal via alyncoin-cli..."
CLI_PATH="$(dirname "$0")/../../build/alyncoin-cli"
if [ ! -x "$CLI_PATH" ]; then
  CLI_PATH="alyncoin-cli"
fi

"$CLI_PATH" dao-finalize "$PROPOSAL_ID"
status=$?
if [ $status -eq 0 ]; then
  echo "Proposal finalized."
else
  echo "Failed to finalize proposal." >&2
fi
