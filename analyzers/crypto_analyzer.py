"""
Crypto Analyzer for CryptoPuzzle-hunter.
Provides advanced cryptographic analysis capabilities beyond classical ciphers.
Specializes in blockchain, wallet analysis, and cryptocurrency forensics.
"""

import os
import hashlib
import base64
import binascii
import re
import json
import requests
from typing import Dict, List, Tuple, Optional, Any, Union
from core.state import State
from core.steganography_tools import analyze_stego, run_zsteg, run_binwalk
from analyzers.base import register_analyzer, analyzer_compatibility


@register_analyzer('crypto_analyzer')
@analyzer_compatibility(requires_text=True)
def analyze_crypto(state: State) -> State:
    """
    Analyze the puzzle for modern cryptographic elements.

    This analyzer focuses on:
    1. Hash identification and cracking attempts
    2. Base64 and other encodings
    3. Modern encryption algorithms
    4. Blockchain-related cryptography
    5. Digital signatures
    6. Wallet file detection and analysis
    7. Private key identification
    8. Blockchain transaction analysis
    9. Smart contract analysis

    Args:
        state: Current puzzle state

    Returns:
        Updated state with crypto analysis insights
    """
    # Analyze text content
    if state.puzzle_text:
        _analyze_text_content(state, state.puzzle_text)

    # Analyze binary data if available
    if state.binary_data:
        _analyze_binary_content(state, state.binary_data)

    # Analyze related files
    for filename, content in state.related_files.items():
        if isinstance(content, bytes):
            _analyze_binary_content(state, content, filename)
        else:
            _analyze_text_content(state, str(content), filename)

    return state


def _analyze_text_content(state: State, text: str, filename: str = None) -> None:
    """Analyze text content for crypto elements."""
    source_info = f" in {filename}" if filename else ""

    # Hash identification
    hashes = identify_hashes(text)
    for hash_type, hash_value in hashes:
        state.add_insight(f"Identified {hash_type} hash: {hash_value[:20]}...{source_info}", "crypto_analyzer")

        # Attempt to crack common hashes
        cracked = attempt_hash_crack(hash_value, hash_type)
        if cracked:
            state.add_transformation(
                f"hash_crack_{hash_type}",
                f"Cracked {hash_type} hash",
                hash_value,
                cracked,
                "crypto_analyzer"
            )

    # Base64 analysis
    base64_strings = identify_and_decode_base64(text)
    for original, decoded in base64_strings:
        state.add_transformation(
            "base64_decode",
            f"Base64 decoded string{source_info}",
            original,
            decoded,
            "crypto_analyzer"
        )

    # Hex analysis
    hex_strings = identify_and_decode_hex(text)
    for original, decoded in hex_strings:
        state.add_transformation(
            "hex_decode",
            f"Hex decoded string{source_info}",
            original,
            decoded,
            "crypto_analyzer"
        )

    # Blockchain address identification
    addresses = identify_blockchain_addresses(text)
    for addr_type, address in addresses:
        state.add_insight(f"Found {addr_type} address: {address}{source_info}", "crypto_analyzer")

        # Analyze Ethereum addresses
        if addr_type == "Ethereum":
            analysis = analyze_ethereum_address(address)
            if analysis:
                state.add_transformation(
                    "ethereum_analysis",
                    f"Ethereum address analysis{source_info}",
                    address,
                    analysis,
                    "crypto_analyzer"
                )

    # PGP/GPG analysis
    pgp_elements = identify_pgp_elements(text)
    for element_type, content in pgp_elements:
        state.add_insight(f"Found {element_type}{source_info}", "crypto_analyzer")
        if len(content) > 100:  # Only store meaningful content
            state.add_transformation(
                f"pgp_{element_type.lower()}",
                f"PGP {element_type}{source_info}",
                "text_content",
                content,
                "crypto_analyzer"
            )

    # Private key identification
    private_keys = identify_private_keys(text)
    for key_type, key_value in private_keys:
        state.add_insight(f"Found potential {key_type} private key{source_info}", "crypto_analyzer")
        state.add_transformation(
            f"private_key_{key_type.lower()}",
            f"Private key ({key_type}){source_info}",
            "text_content",
            key_value,
            "crypto_analyzer"
        )

    # Wallet file analysis
    wallet_files = identify_wallet_files(text)
    for wallet_type, wallet_content in wallet_files:
        state.add_insight(f"Found {wallet_type} wallet data{source_info}", "crypto_analyzer")

        # Try to extract wallet address
        address = extract_wallet_address(wallet_type, wallet_content)
        if address:
            state.add_transformation(
                f"wallet_address_{wallet_type.lower()}",
                f"Extracted {wallet_type} wallet address{source_info}",
                wallet_content[:100] + "...",
                address,
                "crypto_analyzer"
            )

    # Smart contract analysis
    smart_contracts = identify_smart_contracts(text)
    for contract_type, code in smart_contracts:
        state.add_insight(f"Found {contract_type} smart contract code{source_info}", "crypto_analyzer")

        analysis = analyze_smart_contract(contract_type, code)
        if analysis:
            state.add_transformation(
                f"smart_contract_{contract_type.lower()}",
                f"Smart contract analysis ({contract_type}){source_info}",
                code[:100] + "...",
                analysis,
                "crypto_analyzer"
            )


def _analyze_binary_content(state: State, data: bytes, filename: str = None) -> None:
    """Analyze binary content for crypto elements."""
    source_info = f" in {filename}" if filename else ""

    # Wallet file analysis
    wallet_data = analyze_binary_for_wallets(data)
    for wallet_type, wallet_info in wallet_data:
        state.add_insight(f"Found {wallet_type} wallet in binary data{source_info}", "crypto_analyzer")
        state.add_transformation(
            f"binary_wallet_{wallet_type.lower()}",
            f"Binary wallet data ({wallet_type}){source_info}",
            f"<{len(data)} bytes>",
            wallet_info,
            "crypto_analyzer"
        )

    # Look for embedded text that might contain crypto data
    try:
        # Try to decode as UTF-8
        text_content = data.decode('utf-8', errors='ignore')
        if len(text_content) > 20 and any(c.isprintable() for c in text_content):
            _analyze_text_content(state, text_content, filename)
    except:
        pass

    # Basic entropy analysis
    entropy = _calculate_entropy(data)
    if entropy > 7.5:  # High entropy might indicate encryption
        state.add_insight(
            f"High entropy detected ({entropy:.2f}){source_info} - possible encrypted data",
            "crypto_analyzer"
        )
    elif entropy < 2.0:  # Very low entropy
        state.add_insight(
            f"Very low entropy detected ({entropy:.2f}){source_info} - possible simple encoding",
            "crypto_analyzer"
        )


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0

    # Count byte frequencies
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1

    # Calculate entropy
    entropy = 0
    data_len = len(data)
    for freq in frequencies:
        if freq > 0:
            prob = freq / data_len
            entropy -= prob * (prob.bit_length() - 1)

    return entropy


def identify_hashes(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential cryptographic hashes in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (hash_type, hash_value) tuples
    """
    hashes = []

    # Common hash patterns
    hash_patterns = [
        (r'\b[a-fA-F0-9]{32}\b', 'MD5'),
        (r'\b[a-fA-F0-9]{40}\b', 'SHA-1'),
        (r'\b[a-fA-F0-9]{64}\b', 'SHA-256'),
        (r'\b[a-fA-F0-9]{128}\b', 'SHA-512'),
        (r'\b[a-fA-F0-9]{40}\b', 'RIPEMD-160'),
    ]

    for pattern, hash_type in hash_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            if is_likely_hash(match):
                hashes.append((hash_type, match))

    return hashes


def is_likely_hash(hex_string: str) -> bool:
    """
    Check if a hex string is likely to be a hash by analyzing its entropy.

    Args:
        hex_string: Hexadecimal string to check

    Returns:
        True if the string is likely a hash, False otherwise
    """
    if len(hex_string) < 32:  # Too short to be a meaningful hash
        return False

    # Convert to bytes for entropy calculation
    try:
        data = bytes.fromhex(hex_string)
        entropy = _calculate_entropy(data)

        # Hashes typically have high entropy
        return entropy > 6.0
    except ValueError:
        return False


def attempt_hash_crack(hash_value: str, hash_type: str) -> Optional[str]:
    """
    Attempt to crack a hash using a small dictionary of common values.

    Args:
        hash_value: The hash to crack
        hash_type: Type of hash (MD5, SHA1, SHA256)

    Returns:
        Cracked plaintext if successful, None otherwise
    """
    # Common passwords and values for puzzle solving
    common_values = [
        'password', '123456', 'admin', 'root', 'flag', 'secret', 'key',
        'crypto', 'puzzle', 'solve', 'answer', 'hidden', 'treasure',
        'a', 'b', 'c', 'test', 'hello', 'world', '1', '2', '3',
        'flag{', '}', 'ctf', 'challenge', 'bitcoin', 'ethereum',
        '', ' ', '\n', '\t'
    ]

    # Add some common CTF flag formats
    for i in range(100):
        common_values.extend([f'flag{{{i}}}', f'ctf{{{i}}}', f'FLAG{{{i}}}'])

    hash_func = None
    if hash_type == 'MD5':
        hash_func = hashlib.md5
    elif hash_type == 'SHA-1':
        hash_func = hashlib.sha1
    elif hash_type == 'SHA-256':
        hash_func = hashlib.sha256
    elif hash_type == 'SHA-512':
        hash_func = hashlib.sha512

    if not hash_func:
        return None

    hash_value_lower = hash_value.lower()

    for value in common_values:
        try:
            computed_hash = hash_func(value.encode()).hexdigest().lower()
            if computed_hash == hash_value_lower:
                return value
        except:
            continue

    return None


def identify_and_decode_base64(text: str) -> List[Tuple[str, str]]:
    """
    Identify and decode potential Base64 encoded strings.

    Args:
        text: Text to analyze

    Returns:
        List of (original, decoded) tuples
    """
    results = []

    # Base64 pattern - at least 8 characters, ends with 0-2 padding chars
    base64_pattern = r'[A-Za-z0-9+/]{8,}={0,2}'

    matches = re.findall(base64_pattern, text)

    for match in matches:
        # Skip if it's likely a hex string instead
        if re.match(r'^[a-fA-F0-9]+$', match):
            continue

        try:
            # Validate Base64 format
            if len(match) % 4 == 0:  # Valid Base64 length
                decoded_bytes = base64.b64decode(match, validate=True)

                # Try to decode as text
                try:
                    decoded_text = decoded_bytes.decode('utf-8')
                    if decoded_text.isprintable() and len(decoded_text) > 1:
                        results.append((match, decoded_text))
                except UnicodeDecodeError:
                    # If not text, represent as hex
                    decoded_hex = decoded_bytes.hex()
                    results.append((match, f"<binary: {decoded_hex}>"))
        except:
            continue

    return results


def identify_and_decode_hex(text: str) -> List[Tuple[str, str]]:
    """
    Identify and decode potential hexadecimal encoded strings.

    Args:
        text: Text to analyze

    Returns:
        List of (original, decoded) tuples
    """
    results = []

    # Hex pattern - even number of hex characters, at least 8 chars
    hex_patterns = [
        r'\b[a-fA-F0-9]{8,}\b',  # Standard hex
        r'0x[a-fA-F0-9]{6,}',    # 0x prefixed hex
        r'\\x[a-fA-F0-9]{2,}',   # \x prefixed hex
    ]

    for pattern in hex_patterns:
        matches = re.findall(pattern, text)

        for match in matches:
            # Clean up the match
            clean_match = match.replace('0x', '').replace('\\x', '')

            # Must be even length for proper hex decoding
            if len(clean_match) % 2 != 0:
                continue

            try:
                decoded_bytes = bytes.fromhex(clean_match)

                # Try to decode as text
                try:
                    decoded_text = decoded_bytes.decode('utf-8')
                    if decoded_text.isprintable() and len(decoded_text) > 1:
                        results.append((match, decoded_text))
                except UnicodeDecodeError:
                    # Not valid UTF-8, but might be meaningful binary
                    if len(decoded_bytes) >= 4:  # Only store meaningful binary
                        results.append((match, f"<binary: {len(decoded_bytes)} bytes>"))
            except ValueError:
                continue

    return results


def identify_blockchain_addresses(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential blockchain addresses in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (address_type, address) tuples
    """
    addresses = []

    # Bitcoin address patterns
    bitcoin_patterns = [
        (r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', 'Bitcoin'),
        (r'\b[bc]1[a-zA-HJ-NP-Z0-9]{25,87}\b', 'Bitcoin (Bech32)'),
    ]

    # Ethereum address pattern
    ethereum_pattern = r'\b0x[a-fA-F0-9]{40}\b'

    for pattern, addr_type in bitcoin_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            addresses.append((addr_type, match))

    # Ethereum addresses
    matches = re.findall(ethereum_pattern, text)
    for match in matches:
        addresses.append(('Ethereum', match))

    return addresses


def identify_pgp_elements(text: str) -> List[Tuple[str, str]]:
    """
    Identify PGP/GPG elements like signatures, keys, or encrypted messages.

    Args:
        text: Text to analyze

    Returns:
        List of (element_type, content) tuples
    """
    pgp_elements = []

    pgp_patterns = [
        (r'-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----', 'Public Key'),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----(.*?)-----END PGP PRIVATE KEY BLOCK-----', 'Private Key'),
        (r'-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----', 'Encrypted Message'),
        (r'-----BEGIN PGP SIGNATURE-----(.*?)-----END PGP SIGNATURE-----', 'Signature'),
        (r'-----BEGIN PGP SIGNED MESSAGE-----(.*?)-----END PGP SIGNATURE-----', 'Signed Message'),
    ]

    for pattern, element_type in pgp_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            pgp_elements.append((element_type, match.strip()))

    return pgp_elements


def identify_private_keys(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential cryptocurrency private keys in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (key_type, key_value) tuples
    """
    private_keys = []

    # Bitcoin WIF (Wallet Import Format) patterns
    wif_patterns = [
        (r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b', 'Bitcoin WIF'),  # Uncompressed
        (r'\b[KL][1-9A-HJ-NP-Za-km-z]{51}\b', 'Bitcoin WIF Compressed'),
    ]

    for pattern, key_type in wif_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            private_keys.append((key_type, match))

    # Ethereum private key (64 hex chars)
    eth_key_pattern = r'\b[a-fA-F0-9]{64}\b'
    matches = re.findall(eth_key_pattern, text)
    for match in matches:
        # Additional validation - check if it's likely a private key vs hash
        if not is_likely_hash(match):  # Exclude if it looks like a hash
            private_keys.append(('Ethereum Private Key', match))

    # BIP39 mnemonic seed phrases
    words = text.split()
    for i in range(len(words) - 11):  # 12+ word phrases
        phrase = ' '.join(words[i:i+12])
        if is_likely_mnemonic(phrase):
            private_keys.append(('BIP39 Mnemonic', phrase))

    return private_keys


def is_likely_mnemonic(phrase: str) -> bool:
    """
    Check if a phrase is likely to be a BIP39 mnemonic seed phrase.

    Args:
        phrase: The phrase to check

    Returns:
        True if the phrase is likely a mnemonic, False otherwise
    """
    words = phrase.lower().split()

    # Must be 12, 15, 18, 21, or 24 words
    if len(words) not in [12, 15, 18, 21, 24]:
        return False

    # Common BIP39 words (subset for quick check)
    common_bip39_words = {
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb',
        'abstract', 'absurd', 'abuse', 'access', 'accident', 'account',
        'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across',
        'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict',
        'address', 'adjust', 'admit', 'adult', 'advance', 'advice',
        'aerobic', 'affair', 'afford', 'afraid', 'again', 'against',
        'age', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport',
        'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'all',
        'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also',
        'alter', 'always', 'amateur', 'amazing', 'among', 'amount',
        'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle',
        'angry', 'animal', 'ankle', 'announce', 'annual', 'another',
        'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart',
        'apology', 'appear', 'apple', 'approve', 'april', 'arch',
        'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor',
        'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow',
        'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect',
        'assault', 'asset', 'assist', 'assume', 'asthma', 'athlete',
        'atom', 'attack', 'attend', 'attitude', 'attract', 'auction',
        'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
        'average', 'avocado', 'avoid', 'awake', 'aware', 'away',
        'awesome', 'awful', 'awkward', 'axis', 'baby', 'bachelor',
        'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball',
        'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain',
        'barrel', 'base', 'basic', 'basket', 'battle', 'beach',
        'bean', 'beauty', 'because', 'become', 'beef', 'before',
        'begin', 'behave', 'behind', 'believe', 'below', 'belt',
        'bench', 'benefit', 'best', 'betray', 'better', 'between',
        'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology',
        'bird', 'birth', 'bitter', 'black', 'blade', 'blame',
        'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood',
        'blossom', 'blow', 'blue', 'blur', 'blush', 'board',
        'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book',
        'boost', 'border', 'boring', 'borrow', 'boss', 'bottom',
        'bounce', 'box', 'boy', 'bracket', 'brain', 'brand',
        'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge',
        'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken',
        'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble',
        'buddy', 'budget', 'buffalo', 'build', 'bulb', 'bulk',
        'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst',
        'bus', 'business', 'busy', 'butter', 'buyer', 'buzz'
    }

    # Check if most words are in the BIP39 word list
    bip39_word_count = sum(1 for word in words if word in common_bip39_words)

    # If more than 70% of words are in BIP39 list, it's likely a mnemonic
    return bip39_word_count / len(words) > 0.7


def identify_wallet_files(text: str) -> List[Tuple[str, str]]:
    """
    Identify cryptocurrency wallet files in JSON format.

    Args:
        text: Text to analyze

    Returns:
        List of (wallet_type, wallet_content) tuples
    """
    wallet_files = []

    # Look for JSON structures that might be wallet files
    try:
        # Try to parse as JSON
        if text.strip().startswith('{') and text.strip().endswith('}'):
            data = json.loads(text)

            # Check for common wallet file indicators
            wallet_indicators = {
                'Ethereum': ['address', 'crypto', 'cipher', 'ciphertext', 'kdf'],
                'Bitcoin Core': ['bestblock', 'transactions', 'key', 'pool'],
                'Electrum': ['seed_version', 'use_encryption', 'wallet_type'],
                'Metamask': ['data', 'iv', 'salt', 'keystore'],
            }

            for wallet_type, indicators in wallet_indicators.items():
                if isinstance(data, dict) and any(indicator in data for indicator in indicators):
                    wallet_files.append((wallet_type, text))
                    break
    except json.JSONDecodeError:
        pass

    # Look for wallet-like patterns in text
    wallet_patterns = [
        (r'{"address".*?"crypto".*?}', 'Ethereum Keystore'),
        (r'{"version".*?"Crypto".*?}', 'Generic Keystore'),
    ]

    for pattern, wallet_type in wallet_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            wallet_files.append((wallet_type, match))

    return wallet_files


def extract_wallet_address(wallet_type: str, wallet_content: str) -> Optional[str]:
    """
    Extract wallet address from wallet file content.

    Args:
        wallet_type: Type of wallet
        wallet_content: Wallet file content

    Returns:
        Wallet address if found, None otherwise
    """
    try:
        if wallet_type in ['Ethereum', 'Ethereum Keystore']:
            # Try to parse as JSON
            data = json.loads(wallet_content)
            if 'address' in data:
                address = data['address']
                # Add 0x prefix if not present
                if not address.startswith('0x'):
                    address = '0x' + address
                return address

        # Look for address patterns in the content
        eth_pattern = r'0x[a-fA-F0-9]{40}'
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'

        for pattern in [eth_pattern, btc_pattern]:
            match = re.search(pattern, wallet_content)
            if match:
                return match.group(0)

    except:
        pass

    return None


def analyze_binary_for_wallets(binary_data: bytes) -> List[Tuple[str, str]]:
    """
    Analyze binary data for wallet files.

    Args:
        binary_data: Binary data to analyze

    Returns:
        List of (wallet_type, wallet_info) tuples
    """
    wallet_data = []

    # Common wallet file signatures
    wallet_signatures = [
        (b'\x62\x31\x05\x00', 'Bitcoin Core wallet.dat'),
        (b'{"address"', 'Ethereum JSON Keystore'),
        (b'{"version"', 'Generic JSON Keystore'),
        (b'ELECTRUM', 'Electrum Wallet'),
        (b'metamask', 'MetaMask Wallet'),
    ]

    for signature, wallet_type in wallet_signatures:
        if signature in binary_data:
            wallet_data.append((wallet_type, f'Signature found at offset {binary_data.find(signature)}'))

    # Look for encrypted wallet indicators
    if len(binary_data) > 100:
        entropy = _calculate_entropy(binary_data)
        if entropy > 7.8:  # Very high entropy suggests encryption
            wallet_data.append(('Encrypted Wallet', f'High entropy ({entropy:.2f}) suggests encrypted wallet data'))

    return wallet_data


def analyze_ethereum_address(address: str) -> Optional[str]:
    """
    Analyze an Ethereum address using Etherscan API.

    Args:
        address: Ethereum address to analyze

    Returns:
        Analysis results as a string, or None if analysis failed
    """
    try:
        api_key = os.getenv('ETHERSCAN_API_KEY')
        if not api_key:
            return f"Address format: {'valid' if len(address) == 42 and address.startswith('0x') else 'invalid'}"

        # Get basic address info
        url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"

        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == '1':
                balance_wei = int(data.get('result', '0'))
                balance_eth = balance_wei / 10**18

                # Get transaction count
                tx_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest&apikey={api_key}"
                tx_response = requests.get(tx_url, timeout=10)
                tx_count = 0
                if tx_response.status_code == 200:
                    tx_data = tx_response.json()
                    if 'result' in tx_data:
                        tx_count = int(tx_data['result'], 16)

                analysis = f"Balance: {balance_eth:.6f} ETH, Transactions: {tx_count}"

                # Check if it's a contract
                if tx_count == 0 and balance_wei == 0:
                    # Might be a contract, check for code
                    code_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={address}&tag=latest&apikey={api_key}"
                    code_response = requests.get(code_url, timeout=10)
                    if code_response.status_code == 200:
                        code_data = code_response.json()
                        if code_data.get('result', '0x') != '0x':
                            analysis += ", Contract detected"

                return analysis

    except Exception as e:
        return f"Address analysis failed: {str(e)}"

    return None


def identify_smart_contracts(text: str) -> List[Tuple[str, str]]:
    """
    Identify smart contract code in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (contract_type, code) tuples
    """
    contracts = []

    # Solidity contract pattern
    solidity_pattern = r'pragma solidity.*?contract\s+\w+.*?(?=pragma|contract|\Z)'
    matches = re.findall(solidity_pattern, text, re.DOTALL | re.IGNORECASE)
    for match in matches:
        if len(match) > 100:  # Only meaningful contracts
            contracts.append(('Solidity', match.strip()))

    # Vyper contract pattern
    vyper_patterns = [
        r'# @version.*?@external.*?def.*?:',
        r'from vyper.interfaces import.*?@external'
    ]

    for pattern in vyper_patterns:
        matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if len(match) > 50:
                contracts.append(('Vyper', match.strip()))

    # Bytecode patterns (compiled contracts)
    bytecode_pattern = r'0x[a-fA-F0-9]{100,}'
    matches = re.findall(bytecode_pattern, text)
    for match in matches:
        contracts.append(('Bytecode', match))

    return contracts


def analyze_smart_contract(contract_type: str, code: str) -> Optional[str]:
    """
    Perform basic analysis of smart contract code.

    Args:
        contract_type: Type of contract (Solidity, Vyper)
        code: Contract code

    Returns:
        Analysis results as a string, or None if analysis failed
    """
    try:
        analysis_parts = []

        if contract_type == 'Solidity':
            # Look for common patterns
            if 'payable' in code:
                analysis_parts.append('Accepts Ether payments')

            if 'mapping' in code:
                analysis_parts.append('Uses mappings for storage')

            if 'modifier' in code:
                analysis_parts.append('Has custom modifiers')

            if 'event' in code:
                analysis_parts.append('Emits events')

            # Look for security patterns
            if 'require(' in code:
                analysis_parts.append('Uses require() for validation')

            if 'onlyOwner' in code:
                analysis_parts.append('Has owner restrictions')

        elif contract_type == 'Bytecode':
            # Basic bytecode analysis
            if len(code) > 1000:
                analysis_parts.append(f'Large bytecode ({len(code)} chars)')

            # Look for common opcodes
            common_opcodes = ['60', '61', '63', '80', '90', 'f3', 'fd']
            found_opcodes = [op for op in common_opcodes if op in code.lower()]
            if found_opcodes:
                analysis_parts.append(f'Contains opcodes: {", ".join(found_opcodes)}')

        return '; '.join(analysis_parts) if analysis_parts else f'Basic {contract_type} contract detected'

    except Exception as e:
        return f'Contract analysis failed: {str(e)}'


def analyze(state, **kwargs):
    """Wrapper function for compatibility."""
    return analyze_crypto(state)