#!/bin/bash

RPC_URL=$(kurtosis service inspect local-eth-testnet el-1-geth-lighthouse | grep -E '^[[:space:]]*rpc:' | awk -F '-> ' '{print $2}')
RPC_URL="http://$RPC_URL"
echo $RPC_URL
echo $RPC_URL > rpc_url.txt

# Deploy the contract
OUTPUT=$(forge create --private-key "39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d" ./contracts/src/SecureStorage.sol:SecureStorage --broadcast --rpc-url $RPC_URL)

# Extract the deployed to address
DEPLOYED_TO=$(echo "$OUTPUT" | grep -o 'Deployed to: 0x[0-9a-fA-F]*' | sed 's/Deployed to: //')

# Write the deployed address to a file
echo $DEPLOYED_TO > deployed_address.txt