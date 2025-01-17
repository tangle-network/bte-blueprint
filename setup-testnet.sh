#!/bin/bash

# setup test net
kurtosis clean
kurtosis --enclave local-eth-testnet run github.com/ethpandaops/ethereum-package

sleep 20