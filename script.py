import os
import json
import time
import logging
from typing import Dict, Any, Optional, List

import requests
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import BlockNotFound
from dotenv import load_dotenv

# --- Basic Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class ConfigManager:
    """
    Manages application configuration by loading environment variables from a .env file.
    This class centralizes access to configuration parameters, making the application
    easier to configure and maintain.
    """
    def __init__(self, env_file_path: str = '.env'):
        """
        Initializes the ConfigManager and loads environment variables.
        Args:
            env_file_path (str): The path to the .env file.
        """
        load_dotenv(dotenv_path=env_file_path)
        self.source_chain_rpc: Optional[str] = os.getenv('SOURCE_CHAIN_RPC_URL')
        self.dest_chain_rpc: Optional[str] = os.getenv('DEST_CHAIN_RPC_URL')
        self.source_bridge_address: Optional[str] = os.getenv('SOURCE_BRIDGE_CONTRACT_ADDRESS')
        self.source_bridge_abi_path: Optional[str] = os.getenv('SOURCE_BRIDGE_ABI_PATH')
        self.validator_private_key: Optional[str] = os.getenv('VALIDATOR_PRIVATE_KEY') # For simulation purposes
        self.start_block: int = int(os.getenv('START_BLOCK', '0'))
        self.block_scan_interval_sec: int = int(os.getenv('BLOCK_SCAN_INTERVAL_SEC', '15'))
        self.state_file: str = os.getenv('STATE_FILE_PATH', 'var/scanner_state.json')
        self.oracle_api_url: Optional[str] = os.getenv('ORACLE_API_URL')

        self._validate_config()

    def _validate_config(self):
        """Validates that all necessary configuration variables are present."""
        required_vars = [
            'source_chain_rpc', 'dest_chain_rpc', 'source_bridge_address',
            'source_bridge_abi_path', 'validator_private_key', 'oracle_api_url'
        ]
        for var in required_vars:
            if not getattr(self, var):
                raise ValueError(f'Missing required environment variable for: {var.upper()}')
        logging.info("Configuration loaded and validated successfully.")


class BlockchainConnector:
    """
    Handles the connection to a specific blockchain via a Web3 provider.
    It encapsulates the Web3 instance and provides utility methods for interacting
    with the chain, such as loading smart contracts.
    """
    def __init__(self, rpc_url: str):
        """
        Establishes a connection to the blockchain.
        Args:
            rpc_url (str): The RPC URL of the blockchain node.
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to blockchain via RPC: {rpc_url}")
        self.chain_id = self.w3.eth.chain_id
        logging.info(f"Successfully connected to chain ID {self.chain_id} at {rpc_url}")

    def get_contract(self, address: str, abi_path: str) -> Contract:
        """
        Loads and returns a Web3 Contract object.
        Args:
            address (str): The checksummed address of the smart contract.
            abi_path (str): The file path to the contract's ABI JSON file.
        Returns:
            Contract: A Web3 Contract instance.
        """
        try:
            with open(abi_path, 'r') as f:
                abi = json.load(f)
            checksum_address = Web3.to_checksum_address(address)
            return self.w3.eth.contract(address=checksum_address, abi=abi)
        except FileNotFoundError:
            logging.error(f"ABI file not found at path: {abi_path}")
            raise
        except Exception as e:
            logging.error(f"Error loading contract at address {address}: {e}")
            raise


class ExternalOracle:
    """
    Simulates an external oracle that provides additional data for transaction validation.
    This component uses the 'requests' library to fetch data from an external API,
    mimicking how a real-world validator might query for token prices or other off-chain info.
    """
    def __init__(self, api_url: str):
        """
        Initializes the oracle with the API endpoint.
        Args:
            api_url (str): The base URL of the external API to query.
        """
        self.api_url = api_url
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        logging.info(f"External Oracle configured for API: {self.api_url}")

    def validate_transaction_data(self, token: str, amount: int) -> bool:
        """
        Performs a simulated validation check using external data.
        For this simulation, it checks if a token is on a 'whitelist' from the API.
        
        Args:
            token (str): The token address involved in the transaction.
            amount (int): The amount of the token being transferred.
        
        Returns:
            bool: True if the validation passes, False otherwise.
        """
        try:
            # Example: Querying a public API (CoinGecko) for token data as a validation step
            # A real oracle might have a more complex and secure verification process.
            params = {'ids': token.lower(), 'vs_currencies': 'usd'}
            response = self.session.get(self.api_url, params=params)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            data = response.json()

            # Edge Case: API returns empty data for a valid request
            if not data or token.lower() not in data:
                logging.warning(f"Oracle validation failed: Token '{token}' not found in oracle response.")
                return False

            # Simple business logic: is the token price above a certain threshold?
            price = data[token.lower()]['usd']
            if price < 0.01: # Arbitrary threshold for simulation
                 logging.warning(f"Oracle validation failed: Token '{token}' price ${price} is below threshold.")
                 return False

            logging.info(f"Oracle validation successful for token '{token}' with price ${price}.")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Oracle API request failed: {e}")
            return False
        except (KeyError, TypeError) as e:
            logging.error(f"Oracle response parsing error: {e}. Response: {response.text}")
            return False


class EventScanner:
    """
    Scans the source blockchain for specific events within a given block range.
    It manages its state (the last block scanned) to ensure continuity and prevent
    re-processing of events. This is a critical component for any event listener.
    """
    def __init__(self, connector: BlockchainConnector, contract: Contract, state_file: str, start_block: int, event_name: str):
        self.connector = connector
        self.contract = contract
        self.state_file = state_file
        self.event_name = event_name
        self.last_scanned_block = self._load_last_scanned_block(start_block)

    def _load_last_scanned_block(self, default_start_block: int) -> int:
        """
        Loads the last scanned block number from the state file. If the file doesn't exist
        or is invalid, it starts from the configured default start block.
        """
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                block_num = int(state.get('last_scanned_block', default_start_block))
                logging.info(f"Resuming scan from block {block_num} (loaded from state file).")
                return block_num
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            logging.warning(f"State file not found or invalid. Starting scan from default block {default_start_block}.")
            return default_start_block

    def _save_last_scanned_block(self, block_number: int):
        """
        Saves the last successfully scanned block number to the state file.
        This ensures that the scanner can resume from where it left off after a restart.
        """
        with open(self.state_file, 'w') as f:
            json.dump({'last_scanned_block': block_number}, f)

    def scan_for_events(self) -> List[Dict[str, Any]]:
        """
        Scans a range of blocks for new events.
        It handles the case where the `to_block` is ahead of the current chain head.
        
        Returns:
            List[Dict[str, Any]]: A list of decoded event logs.
        """
        try:
            latest_block = self.connector.w3.eth.block_number
            from_block = self.last_scanned_block + 1
            
            # To avoid scanning too far ahead and getting errors, scan up to the latest confirmed block.
            # A small buffer (e.g., 1 block) is added for chain stability.
            to_block = latest_block - 1 

            if from_block > to_block:
                logging.info(f"No new blocks to scan. Current head: {latest_block}, last scanned: {self.last_scanned_block}")
                return []

            logging.info(f"Scanning for '{self.event_name}' events from block {from_block} to {to_block}...")
            
            event_filter = getattr(self.contract.events, self.event_name).create_filter(
                fromBlock=from_block,
                toBlock=to_block
            )
            events = event_filter.get_all_entries()

            if events:
                logging.info(f"Found {len(events)} new '{self.event_name}' event(s).")

            self.last_scanned_block = to_block
            self._save_last_scanned_block(to_block)

            return events
        except BlockNotFound:
            logging.warning("Scan range is ahead of chain head. Will retry.")
            return []
        except Exception as e:
            logging.error(f"An unexpected error occurred during event scanning: {e}")
            # In a production system, you might want to rollback last_scanned_block or handle differently
            return []


class BridgeEventHandler:
    """
    Processes events captured by the EventScanner.
    This class contains the core business logic of the bridge validator. For each
    'Deposit' event, it triggers validation and simulates the minting/release
    of tokens on the destination chain.
    """
    def __init__(self, dest_connector: BlockchainConnector, oracle: ExternalOracle, validator_key: str):
        self.dest_connector = dest_connector
        self.oracle = oracle
        self.validator_account = self.dest_connector.w3.eth.account.from_key(validator_key)
        logging.info(f"Event handler initialized for validator address: {self.validator_account.address}")

    def process_deposit_event(self, event: Dict[str, Any]):
        """
        Handles a single deposit event.
        
        Args:
            event (Dict[str, Any]): The event log data from web3.py.
        """
        try:
            tx_hash = event['transactionHash'].hex()
            args = event['args']
            logging.info(f"Processing Deposit event from tx {tx_hash}: {args}")

            # --- 1. Data Extraction ---
            user = args.get('user')
            token = args.get('token')
            amount = args.get('amount')
            dest_chain_id = args.get('destinationChainId')

            # Edge case: Event data is malformed or missing required fields
            if not all([user, token, amount, dest_chain_id]):
                logging.error(f"Malformed event data in tx {tx_hash}. Skipping.")
                return
            
            # --- 2. Validation ---
            # In a real bridge, this would involve checking consensus, transaction finality, etc.
            # Here, we use our external oracle for a simulated validation check.
            if not self.oracle.validate_transaction_data("ethereum", amount):
                logging.warning(f"Oracle validation failed for deposit in tx {tx_hash}. Aborting cross-chain action.")
                return
            
            # --- 3. Simulate Destination Chain Action ---
            # In a real system, this would involve signing and sending a transaction to the destination
            # bridge contract to release/mint the corresponding tokens.
            self._simulate_mint_on_destination(user, token, amount, tx_hash)

        except Exception as e:
            logging.error(f"Failed to process event {event.get('transactionHash', 'N/A')}: {e}")

    def _simulate_mint_on_destination(self, user: str, token: str, amount: int, source_tx_hash: str):
        """
        Simulates the action of creating and sending a transaction on the destination chain.
        """
        logging.info("--- SIMULATING DESTINATION CHAIN TRANSACTION ---")
        logging.info(f"  Validator: {self.validator_account.address}")
        logging.info(f"  Action: Mint {amount} of token {token} for user {user}")
        logging.info(f"  Source Tx: {source_tx_hash}")
        logging.info(f"  Destination Chain ID: {self.dest_connector.chain_id}")
        # In a real implementation:
        # 1. Build transaction (e.g., contract.functions.mint(...).build_transaction(...))
        # 2. Sign transaction (w3.eth.account.sign_transaction(...))
        # 3. Send raw transaction (w3.eth.send_raw_transaction(...))
        # 4. Wait for transaction receipt
        logging.info("--- SIMULATION COMPLETE ---")


class BridgeListener:
    """
    The main orchestrator class that wires all components together and runs the main loop.
    """
    def __init__(self):
        self.config = ConfigManager()
        
        # Setup for Source Chain
        self.source_connector = BlockchainConnector(self.config.source_chain_rpc)
        self.source_bridge_contract = self.source_connector.get_contract(
            self.config.source_bridge_address,
            self.config.source_bridge_abi_path
        )
        self.scanner = EventScanner(
            self.source_connector,
            self.source_bridge_contract,
            self.config.state_file,
            self.config.start_block,
            event_name='Deposit' # The specific event we are listening for
        )
        
        # Setup for Destination Chain and Handler
        self.dest_connector = BlockchainConnector(self.config.dest_chain_rpc)
        self.oracle = ExternalOracle(self.config.oracle_api_url)
        self.handler = BridgeEventHandler(
            self.dest_connector,
            self.oracle,
            self.config.validator_private_key
        )

    def run(self):
        """
        Starts the main event listening loop.
        """
        logging.info("Starting Cross-Chain Bridge Event Listener...")
        try:
            while True:
                events = self.scanner.scan_for_events()
                for event in events:
                    self.handler.process_deposit_event(event)
                
                logging.info(f"Scan cycle complete. Waiting for {self.config.block_scan_interval_sec} seconds...")
                time.sleep(self.config.block_scan_interval_sec)
        except KeyboardInterrupt:
            logging.info("Shutdown signal received. Exiting...")
        except Exception as e:
            logging.critical(f"A critical error occurred in the main loop: {e}", exc_info=True)


if __name__ == '__main__':
    # To run this simulation, you need:
    # 1. A .env file with the required configuration.
    # 2. A JSON ABI file for the source bridge contract.
    # 3. An internet connection for RPCs and the oracle API.
    
    # Example ABI file (e.g., source_abi.json):
    # [{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"}, ...],"name":"Deposit","type":"event"}]
    
    # Example .env file:
    # SOURCE_CHAIN_RPC_URL=https://rpc.sepolia.org
    # DEST_CHAIN_RPC_URL=https://rpc.goerli.linea.build
    # SOURCE_BRIDGE_CONTRACT_ADDRESS=0x123...abc
    # SOURCE_BRIDGE_ABI_PATH=./config/source_abi.json
    # VALIDATOR_PRIVATE_KEY=0x... (your private key)
    # START_BLOCK=5000000
    # ORACLE_API_URL=https://api.coingecko.com/api/v3/simple/price

    listener = BridgeListener()
    listener.run()
 
# @-internal-utility-start
# Historical update 2025-10-12 21:14:54
def historical_feature_2283():
    """Feature added on 2025-10-12 21:14:54"""
    print('Historical feature working')
    return True
# @-internal-utility-end

