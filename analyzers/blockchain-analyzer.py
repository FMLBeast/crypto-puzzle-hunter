"""
Blockchain analyzer module for Crypto Hunter

This module provides functions for analyzing blockchain data,
including Ethereum addresses, transactions, and encoded messages.
"""
import logging
import re
import binascii
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple, Union
import requests

from core.state import State
from analyzers.base import register_analyzer, analyzer_compatibility
import config

logger = logging.getLogger(__name__)

# Try to import web3 for Ethereum interactions
try:
    from web3 import Web3
    from eth_utils import decode_hex, to_checksum_address, is_address
    WEB3_AVAILABLE = True
except ImportError:
    logger.warning("Web3 not available, Ethereum analysis will be limited")
    WEB3_AVAILABLE = False

# Infura endpoint for Ethereum API access
INFURA_ENDPOINT = f"https://mainnet.infura.io/v3/{config.ETHERSCAN_API_KEY}" if config.ETHERSCAN_API_KEY else None


@register_analyzer("blockchain_analyze")
def analyze_blockchain(state: State) -> State:
    """
    Main blockchain analyzer function that orchestrates blockchain analysis.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    # Run various blockchain analysis functions
    state = detect_addresses(state)
    state = analyze_ethereum_data(state)
    state = check_encoded_messages(state)
    
    return state


@register_analyzer("detect_addresses")
def detect_addresses(state: State) -> State:
    """
    Detect blockchain addresses in the puzzle data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    # Check for addresses in text
    if state.puzzle_text:
        # Ethereum addresses
        eth_addresses = set(re.findall(r'0x[a-fA-F0-9]{40}', state.puzzle_text))
        
        if eth_addresses:
            state.add_insight(
                f"Found {len(eth_addresses)} Ethereum address(es)",
                analyzer="blockchain_analyzer",
                data={"addresses": list(eth_addresses)}
            )
            
            # Validate addresses
            valid_addresses = []
            for addr in eth_addresses:
                if WEB3_AVAILABLE and is_address(addr):
                    try:
                        checksum_addr = to_checksum_address(addr)
                        valid_addresses.append(checksum_addr)
                    except:
                        pass
                elif is_ethereum_address(addr):
                    valid_addresses.append(addr)
            
            if valid_addresses:
                state.add_insight(
                    f"Validated {len(valid_addresses)} Ethereum address(es)",
                    analyzer="blockchain_analyzer",
                    data={"valid_addresses": valid_addresses}
                )
                
                # Add metadata for further analysis
                if "eth_addresses" not in state.metadata:
                    state.metadata["eth_addresses"] = valid_addresses
        
        # Bitcoin addresses
        btc_addresses = set(re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', state.puzzle_text))
        
        if btc_addresses:
            state.add_insight(
                f"Found {len(btc_addresses)} potential Bitcoin address(es)",
                analyzer="blockchain_analyzer",
                data={"addresses": list(btc_addresses)}
            )
            
            # Validate addresses
            valid_addresses = []
            for addr in btc_addresses:
                if is_bitcoin_address(addr):
                    valid_addresses.append(addr)
            
            if valid_addresses:
                state.add_insight(
                    f"Validated {len(valid_addresses)} Bitcoin address(es)",
                    analyzer="blockchain_analyzer",
                    data={"valid_addresses": valid_addresses}
                )
                
                # Add metadata for further analysis
                if "btc_addresses" not in state.metadata:
                    state.metadata["btc_addresses"] = valid_addresses
    
    # Check for addresses in binary data
    if state.puzzle_data:
        data_str = state.puzzle_data.decode('utf-8', errors='ignore')
        
        # Ethereum addresses
        eth_addresses = set(re.findall(r'0x[a-fA-F0-9]{40}', data_str))
        
        if eth_addresses:
            state.add_insight(
                f"Found {len(eth_addresses)} Ethereum address(es) in binary data",
                analyzer="blockchain_analyzer",
                data={"addresses": list(eth_addresses)}
            )
            
            # Validate addresses
            valid_addresses = []
            for addr in eth_addresses:
                if WEB3_AVAILABLE and is_address(addr):
                    try:
                        checksum_addr = to_checksum_address(addr)
                        valid_addresses.append(checksum_addr)
                    except:
                        pass
                elif is_ethereum_address(addr):
                    valid_addresses.append(addr)
            
            if valid_addresses and "eth_addresses" not in state.metadata:
                state.metadata["eth_addresses"] = valid_addresses
        
        # Bitcoin addresses
        btc_addresses = set(re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', data_str))
        
        if btc_addresses:
            state.add_insight(
                f"Found {len(btc_addresses)} potential Bitcoin address(es) in binary data",
                analyzer="blockchain_analyzer",
                data={"addresses": list(btc_addresses)}
            )
            
            # Validate addresses
            valid_addresses = []
            for addr in btc_addresses:
                if is_bitcoin_address(addr):
                    valid_addresses.append(addr)
            
            if valid_addresses and "btc_addresses" not in state.metadata:
                state.metadata["btc_addresses"] = valid_addresses
    
    return state


@register_analyzer("analyze_ethereum_data")
def analyze_ethereum_data(state: State) -> State:
    """
    Analyze Ethereum addresses and transactions.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    # Check if we have Ethereum addresses to analyze
    if "eth_addresses" not in state.metadata or not state.metadata["eth_addresses"]:
        return state
    
    addresses = state.metadata["eth_addresses"]
    
    # Check transaction data
    for address in addresses:
        tx_data = get_ethereum_transactions(address)
        
        if tx_data:
            state.add_insight(
                f"Found transaction data for Ethereum address {address}",
                analyzer="blockchain_analyzer",
                data={"address": address, "transaction_count": len(tx_data)}
            )
            
            # Look for interesting transactions
            interesting_txs = find_interesting_transactions(tx_data)
            
            if interesting_txs:
                for tx in interesting_txs:
                    state.add_insight(
                        f"Interesting transaction found: {tx['reason']} - {tx['hash']}",
                        analyzer="blockchain_analyzer",
                        data={"transaction": tx}
                    )
            
            # Look for data in transactions
            data_txs = find_transactions_with_data(tx_data)
            
            if data_txs:
                for tx in data_txs:
                    state.add_insight(
                        f"Transaction with data found: {tx['hash']}",
                        analyzer="blockchain_analyzer",
                        data={"transaction": tx}
                    )
                    
                    # Try to decode data
                    decoded = decode_transaction_data(tx['data'])
                    if decoded:
                        state.add_transformation(
                            name="decode_tx_data",
                            description=f"Decoded data from transaction {tx['hash']}",
                            input_data=tx['data'],
                            output_data=decoded,
                            analyzer="blockchain_analyzer"
                        )
    
    # Check for contract data
    for address in addresses:
        if is_contract_address(address):
            state.add_insight(
                f"Address {address} is a contract",
                analyzer="blockchain_analyzer"
            )
            
            # Get contract code
            code = get_contract_code(address)
            if code:
                state.add_insight(
                    f"Retrieved contract code for {address}",
                    analyzer="blockchain_analyzer"
                )
                
                state.add_transformation(
                    name="extract_contract_code",
                    description=f"Extracted contract code from {address}",
                    input_data=address,
                    output_data=code,
                    analyzer="blockchain_analyzer"
                )
                
                # Look for interesting patterns in code
                if "constructor" in code:
                    state.add_insight(
                        f"Contract {address} has a constructor function",
                        analyzer="blockchain_analyzer"
                    )
                
                if "transfer" in code:
                    state.add_insight(
                        f"Contract {address} has transfer functionality",
                        analyzer="blockchain_analyzer"
                    )
                
                if "event" in code:
                    state.add_insight(
                        f"Contract {address} defines events",
                        analyzer="blockchain_analyzer"
                    )
    
    return state


@register_analyzer("check_encoded_messages")
def check_encoded_messages(state: State) -> State:
    """
    Check for encoded messages in blockchain data.

    Args:
        state: Current puzzle state

    Returns:
        Updated state after analysis
    """
    # Check if we have Ethereum addresses to analyze
    if "eth_addresses" not in state.metadata or not state.metadata["eth_addresses"]:
        return state
    
    addresses = state.metadata["eth_addresses"]
    
    # Check if addresses encode a message
    message = address_to_message(addresses)
    if message:
        state.add_insight(
            f"Ethereum addresses may encode a message: {message}",
            analyzer="blockchain_analyzer",
            data={"message": message}
        )
        
        state.add_transformation(
            name="address_to_message",
            description="Decoded message from Ethereum addresses",
            input_data=", ".join(addresses),
            output_data=message,
            analyzer="blockchain_analyzer"
        )
    
    # Check for OP_RETURN data in Bitcoin transactions
    if "btc_addresses" in state.metadata and state.metadata["btc_addresses"]:
        btc_addresses = state.metadata["btc_addresses"]
        
        for address in btc_addresses:
            op_return_data = get_bitcoin_op_return(address)
            
            if op_return_data:
                state.add_insight(
                    f"Found OP_RETURN data for Bitcoin address {address}",
                    analyzer="blockchain_analyzer",
                    data={"address": address, "op_return": op_return_data}
                )
                
                # Try to decode as ASCII
                for data in op_return_data:
                    try:
                        decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
                        if any(c.isalnum() for c in decoded):
                            state.add_transformation(
                                name="decode_op_return",
                                description=f"Decoded OP_RETURN data from Bitcoin transaction",
                                input_data=data,
                                output_data=decoded,
                                analyzer="blockchain_analyzer"
                            )
                    except:
                        pass
    
    return state


# Helper functions

def is_ethereum_address(address: str) -> bool:
    """
    Check if a string is a valid Ethereum address.
    
    Args:
        address: Address string to check
        
    Returns:
        True if valid, False otherwise
    """
    if WEB3_AVAILABLE:
        return is_address(address)
    else:
        # Basic validation without web3
        if not address.startswith('0x'):
            return False
        
        if len(address) != 42:  # 0x + 40 hex chars
            return False
        
        # Check if it's a valid hex string
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False


def is_bitcoin_address(address: str) -> bool:
    """
    Check if a string is a valid Bitcoin address.
    
    Args:
        address: Address string to check
        
    Returns:
        True if valid, False otherwise
    """
    # Very basic validation - just check format
    # A more thorough validation would check the checksum
    if not address:
        return False
    
    # Legacy addresses start with 1
    if address.startswith('1'):
        return len(address) >= 26 and len(address) <= 35
    
    # P2SH addresses start with 3
    if address.startswith('3'):
        return len(address) >= 26 and len(address) <= 35
    
    # Bech32 addresses start with bc1
    if address.startswith('bc1'):
        return len(address) >= 14 and len(address) <= 74
    
    return False


def get_ethereum_transactions(address: str) -> List[Dict[str, Any]]:
    """
    Get transaction data for an Ethereum address.
    
    Args:
        address: Ethereum address
        
    Returns:
        List of transaction data or empty list if failed
    """
    if not INFURA_ENDPOINT:
        return []
    
    try:
        if WEB3_AVAILABLE:
            # Use web3 to get transactions
            w3 = Web3(Web3.HTTPProvider(INFURA_ENDPOINT))
            
            # Get the latest 10 transactions (requires full node or archive node)
            # Since we use Infura, we'll use Etherscan API instead for more data
            pass
        
        # Use Etherscan API as fallback or primary method
        if config.ETHERSCAN_API_KEY:
            api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey={config.ETHERSCAN_API_KEY}"
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "1" and "result" in data:
                    return data["result"][:20]  # Return first 20 transactions
        
        return []
    
    except Exception as e:
        logger.debug(f"Error getting Ethereum transactions: {e}")
        return []


def find_interesting_transactions(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find interesting transactions for cryptographic puzzles.
    
    Args:
        transactions: List of transaction data
        
    Returns:
        List of interesting transactions with reasons
    """
    interesting = []
    
    for tx in transactions:
        if "input" in tx and tx["input"] != "0x":
            tx_with_reason = tx.copy()
            tx_with_reason["reason"] = "Contains data"
            tx_with_reason["data"] = tx["input"]
            interesting.append(tx_with_reason)
        
        if "value" in tx and tx["value"] != "0" and int(tx["value"], 16 if tx["value"].startswith("0x") else 10) > 0:
            # Check for value in wei that might encode ASCII
            value_wei = int(tx["value"], 16 if tx["value"].startswith("0x") else 10)
            if 1000000000000000 <= value_wei <= 10000000000000000000:  # Between 0.001 and 10 ETH
                # Check if value might encode chars
                value_str = str(value_wei)
                potential_ascii = []
                
                for i in range(0, len(value_str) - 2, 2):
                    char_code = int(value_str[i:i+2])
                    if 32 <= char_code <= 126:  # Printable ASCII
                        potential_ascii.append(chr(char_code))
                
                ascii_text = "".join(potential_ascii)
                if len(ascii_text) >= 3 and any(c.isalpha() for c in ascii_text):
                    tx_with_reason = tx.copy()
                    tx_with_reason["reason"] = f"Value might encode ASCII: {ascii_text}"
                    tx_with_reason["ascii"] = ascii_text
                    interesting.append(tx_with_reason)
    
    return interesting


def find_transactions_with_data(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find transactions containing data.
    
    Args:
        transactions: List of transaction data
        
    Returns:
        List of transactions with data
    """
    with_data = []
    
    for tx in transactions:
        if "input" in tx and tx["input"] != "0x" and len(tx["input"]) > 10:
            tx_with_data = {
                "hash": tx.get("hash"),
                "from": tx.get("from"),
                "to": tx.get("to"),
                "data": tx["input"],
                "value": tx.get("value")
            }
            with_data.append(tx_with_data)
    
    return with_data


def decode_transaction_data(data: str) -> Optional[str]:
    """
    Attempt to decode transaction data.
    
    Args:
        data: Transaction data (hex string)
        
    Returns:
        Decoded data or None if not decodable
    """
    if not data or data == "0x" or len(data) <= 2:
        return None
    
    try:
        # Remove 0x prefix
        if data.startswith("0x"):
            data = data[2:]
        
        # Try to decode as UTF-8
        binary_data = bytes.fromhex(data)
        
        # Check for ASCII text
        text = binary_data.decode('utf-8', errors='replace')
        
        # If it contains mostly printable chars, return it
        printable_chars = sum(32 <= b <= 126 for b in binary_data)
        if printable_chars / len(binary_data) > 0.5:
            return text
        
        # Try to decode function signature
        if len(data) >= 8:
            function_sig = data[:8]
            return f"Function signature: 0x{function_sig}"
        
        return None
    
    except Exception as e:
        logger.debug(f"Error decoding transaction data: {e}")
        return None


def is_contract_address(address: str) -> bool:
    """
    Check if an Ethereum address is a contract.
    
    Args:
        address: Ethereum address
        
    Returns:
        True if contract, False otherwise
    """
    if not WEB3_AVAILABLE or not INFURA_ENDPOINT:
        return False
    
    try:
        w3 = Web3(Web3.HTTPProvider(INFURA_ENDPOINT))
        code = w3.eth.get_code(to_checksum_address(address))
        return code != b'' and code != '0x'
    except Exception as e:
        logger.debug(f"Error checking if address is contract: {e}")
        return False


def get_contract_code(address: str) -> Optional[str]:
    """
    Get the bytecode of a contract.
    
    Args:
        address: Ethereum address
        
    Returns:
        Contract code or None if not available
    """
    if not WEB3_AVAILABLE or not INFURA_ENDPOINT:
        return None
    
    try:
        w3 = Web3(Web3.HTTPProvider(INFURA_ENDPOINT))
        code = w3.eth.get_code(to_checksum_address(address))
        
        if code == b'' or code == '0x':
            return None
        
        return code.hex()
    except Exception as e:
        logger.debug(f"Error getting contract code: {e}")
        
        # Try Etherscan API as fallback
        if config.ETHERSCAN_API_KEY:
            try:
                api_url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={config.ETHERSCAN_API_KEY}"
                response = requests.get(api_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "1" and "result" in data and data["result"]:
                        return data["result"][0].get("SourceCode")
            except Exception as e2:
                logger.debug(f"Error getting contract code from Etherscan: {e2}")
        
        return None


def address_to_message(addresses: List[str]) -> Optional[str]:
    """
    Check if a list of addresses might encode a message.
    
    Args:
        addresses: List of Ethereum addresses
        
    Returns:
        Decoded message or None if no message found
    """
    if not addresses:
        return None
    
    # Try decoding last 20 bytes (40 hex chars) as ASCII
    potential_message = ""
    
    for address in addresses:
        if not address.startswith("0x") or len(address) != 42:
            continue
        
        # Get the last 40 hex chars (20 bytes)
        hex_part = address[2:]
        
        # Try to decode as ASCII, 2 hex chars at a time
        ascii_chars = []
        for i in range(0, len(hex_part), 2):
            byte_val = int(hex_part[i:i+2], 16)
            if 32 <= byte_val <= 126:  # Printable ASCII
                ascii_chars.append(chr(byte_val))
            else:
                ascii_chars.append(".")  # Non-printable
        
        potential_message += "".join(ascii_chars)
    
    # Check if the result looks like text
    if not potential_message:
        return None
    
    # Look for 3+ consecutive alphanumeric/space chars
    alpha_runs = re.findall(r'[A-Za-z0-9 ]{3,}', potential_message)
    if alpha_runs:
        return " ".join(alpha_runs)
    
    return None


def get_bitcoin_op_return(address: str) -> List[str]:
    """
    Get OP_RETURN data from transactions involving a Bitcoin address.
    
    Args:
        address: Bitcoin address
        
    Returns:
        List of OP_RETURN data
    """
    # Bitcoin doesn't have a standardized free API like Ethereum
    # For this function, we'd need to use a service like BlockCypher
    # This is a simplified implementation
    
    try:
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            op_returns = []
            
            # Get transaction hashes
            tx_hashes = data.get("txrefs", [])
            
            # Get up to 5 transactions to check for OP_RETURN
            for i, tx_ref in enumerate(tx_hashes[:5]):
                tx_hash = tx_ref.get("tx_hash")
                if not tx_hash:
                    continue
                
                tx_url = f"https://api.blockcypher.com/v1/btc/main/txs/{tx_hash}"
                tx_response = requests.get(tx_url, timeout=10)
                
                if tx_response.status_code == 200:
                    tx_data = tx_response.json()
                    
                    # Look for OP_RETURN in outputs
                    for output in tx_data.get("outputs", []):
                        script = output.get("script")
                        if script and script.startswith("6a"):  # OP_RETURN
                            op_returns.append(script[2:])  # Remove OP_RETURN opcode
            
            return op_returns
        
        return []
    
    except Exception as e:
        logger.debug(f"Error getting Bitcoin OP_RETURN data: {e}")
        return []
