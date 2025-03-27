# lst-work: Cross-Chain Bridge Event Listener Simulation

This repository contains a Python-based simulation of a validator/listener node for a cross-chain bridge. The script is designed to monitor a source blockchain for specific events (e.g., `Deposit` events), validate them using external data, and then simulate the corresponding action (e.g., minting tokens) on a destination chain. 

This project serves as an architectural blueprint for building robust, off-chain components for decentralized systems.

## Concept

A cross-chain bridge allows users to transfer assets or data from one blockchain to another. A critical component of most bridge architectures is a set of off-chain nodes (often called validators, relayers, or guardians) that listen for events on the source chain.

When a user deposits assets into the bridge contract on Chain A, the contract emits an event. The validator nodes detect this event, verify its legitimacy and finality, and then collectively sign a message or transaction to authorize the release or minting of an equivalent asset on Chain B.

This script simulates the core logic of one such validator node. It connects to a source chain, scans for `Deposit` events, performs a mock validation using a real-world public API (acting as an oracle), and logs the simulated action it would take on the destination chain.

## Code Architecture

The application is designed with a clear separation of concerns, using distinct classes for different responsibilities. This modular architecture makes the system easier to understand, test, and extend.

-   `ConfigManager`: Responsible for loading all necessary configuration from a `.env` file. It centralizes environment-specific parameters like RPC URLs, contract addresses, and API keys, ensuring that the core application logic remains configuration-agnostic.

-   `BlockchainConnector`: A wrapper around the `web3.py` library. It manages the connection to a specific blockchain node via its RPC URL. It provides helper methods to check the connection status and instantiate contract objects from an address and ABI file.

-   `ExternalOracle`: Simulates an off-chain oracle. This class uses the `requests` library to fetch data from an external API (e.g., CoinGecko). In this simulation, it's used to perform a validation check on the deposited asset, mimicking a real-world scenario where a validator might need external data (like token prices or security scores) to approve a transaction.

-   `EventScanner`: The heart of the listening mechanism. This class is responsible for scanning the source blockchain for new events. It maintains a persistent state in a local file (`scanner_state.json`) to remember the last block it scanned. This prevents re-processing events and ensures it can resume from where it left off after a restart.

-   `BridgeEventHandler`: Contains the primary business logic. When the `EventScanner` finds a new `Deposit` event, it passes it to this handler. The handler extracts the event data, uses the `ExternalOracle` to validate it, and then simulates the corresponding transaction on the destination chain (e.g., minting tokens for the user).

-   `BridgeListener`: The main orchestrator class. It initializes all the other components, wiring them together based on the loaded configuration. It contains the main `run()` loop that periodically triggers the event scanner and processes the results.

### Interaction Flow

```
+------------------+     1. Initialize      +-----------------+
| BridgeListener   |---------------------->|  ConfigManager  |
| (Main Loop)      |                       +-----------------+
+--------+---------+
         |
         | 2. Setup Connections & Contracts
         v
+--------+-----------------+      +----------------------+
|  BlockchainConnector     |      |  BridgeEventHandler  |
|  (Source & Destination)  |      +-----------+----------+
+--------+-----------------+                  |
         |                                  | 3. Needs Validation Data
         |                                  v
         | 4. Scan for Events       +------------------+
         v                          | ExternalOracle   |
+--------+---------+                +------------------+
|   EventScanner   |--- 5. Events -->| (Processes Events) |
+------------------+     Found      +------------------+
```

## How it Works

1.  **Initialization**: The `BridgeListener` class is instantiated. It first creates a `ConfigManager` to load all required settings from the `.env` file.
2.  **Connection Setup**: It then creates two instances of `BlockchainConnector`, one for the source chain and one for the destination chain, using the RPC URLs from the configuration.
3.  **Component Wiring**: The `EventScanner` is set up with the source chain connector and the source bridge contract. The `BridgeEventHandler` is set up with the destination chain connector, the `ExternalOracle`, and the validator's private key.
4.  **Main Loop Starts**: The `run()` method begins an infinite loop.
5.  **Scanning**: Inside the loop, `EventScanner.scan_for_events()` is called. It determines the correct block range to scan (from the last scanned block to the latest confirmed block) and queries the source chain RPC for `Deposit` events.
6.  **State Management**: After each scan, the `EventScanner` updates its state file with the latest block number it has processed.
7.  **Event Processing**: If any events are found, they are passed one by one to `BridgeEventHandler.process_deposit_event()`.
8.  **Validation**: The event handler extracts details from the event log (user, token, amount). It then calls `ExternalOracle.validate_transaction_data()` which makes an HTTP request to an external API to perform a mock validation.
9.  **Simulated Action**: If validation is successful, the handler logs a detailed message describing the transaction it would sign and send on the destination chain to complete the cross-chain transfer.
10. **Wait**: The loop then pauses for a configurable interval (`BLOCK_SCAN_INTERVAL_SEC`) before starting the next scan cycle.

## Usage Example

### 1. Project Setup

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/your-username/lst-work.git
cd lst-work
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

### 2. Install Dependencies

Install the required Python libraries from `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. Create Configuration Files

**a. Create a `.env` file** in the root directory and populate it with your specific details. Use a public RPC provider like Infura, Alchemy, or a public node URL.

**Note**: The contract address and private key are just examples. For a real test, you would need a deployed contract and a funded wallet.

```dotenv
# .env

# RPC URLs for the source and destination chains
SOURCE_CHAIN_RPC_URL=https://rpc.sepolia.org
DEST_CHAIN_RPC_URL=https://rpc-amoy.polygon.technology

# Address of the bridge contract on the source chain
SOURCE_BRIDGE_CONTRACT_ADDRESS=0x0000000000000000000000000000000000000000

# Path to the ABI file for the source bridge contract
SOURCE_BRIDGE_ABI_PATH=./config/source_abi.json

# Private key of the validator account (used for signing on the destination chain)
# IMPORTANT: Use a key from a test wallet with no real funds!
VALIDATOR_PRIVATE_KEY=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# The block number to start scanning from if no state file is found
START_BLOCK=5400000

# How many seconds to wait between scanning for new blocks
BLOCK_SCAN_INTERVAL_SEC=30

# Path to the file for persisting the last scanned block
STATE_FILE_PATH=var/scanner_state.json

# API URL for the external oracle validation
ORACLE_API_URL=https://api.coingecko.com/api/v3/simple/price
```

**b. Create the contract ABI file**. Make a directory `config` and inside it, create a file named `source_abi.json`. This file must contain the ABI for the event you want to listen for. Here is a minimal example for a `Deposit` event:

```json
// config/source_abi.json
[
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "internalType": "address",
        "name": "user",
        "type": "address"
      },
      {
        "indexed": true,
        "internalType": "address",
        "name": "token",
        "type": "address"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "amount",
        "type": "uint256"
      },
      {
        "indexed": false,
        "internalType": "uint256",
        "name": "destinationChainId",
        "type": "uint256"
      }
    ],
    "name": "Deposit",
    "type": "event"
  }
]
```

### 4. Run the Script

Execute the main script from the root directory:

```bash
python script.py
```

The listener will start, connect to the chains, and begin scanning for events. You will see log messages in your console detailing its activity.