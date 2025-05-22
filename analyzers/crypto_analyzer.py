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

@register_analyzer("crypto_analyzer")
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
    text = state.puzzle_text

    # Skip if no text content
    if not text:
        return state

    state.add_insight("Running crypto specialist analysis...", analyzer="crypto_analyzer")

    # Check for hashes
    hash_results = identify_hashes(text)
    if hash_results:
        for hash_type, hash_value in hash_results:
            state.add_insight(f"Identified potential {hash_type} hash: {hash_value}", analyzer="crypto_analyzer")

            # Try to crack common hashes
            if hash_type in ["MD5", "SHA1", "SHA256"]:
                cracked = attempt_hash_crack(hash_value, hash_type)
                if cracked:
                    state.add_insight(f"Cracked {hash_type} hash {hash_value}: {cracked}", analyzer="crypto_analyzer")
                    state.add_transformation(
                        name=f"{hash_type} hash crack",
                        description=f"Cracked {hash_type} hash to plaintext",
                        input_data=hash_value,
                        output_data=cracked,
                        analyzer="crypto_analyzer"
                    )

    # Check for base64 encoded data
    base64_results = identify_and_decode_base64(text)
    if base64_results:
        for original, decoded in base64_results:
            state.add_insight(f"Decoded Base64 data: {original[:20]}... -> {decoded[:30]}...", analyzer="crypto_analyzer")
            state.add_transformation(
                name="Base64 decode",
                description="Decoded Base64 data to plaintext/binary",
                input_data=original,
                output_data=decoded,
                analyzer="crypto_analyzer"
            )

    # Check for hex encoded data
    hex_results = identify_and_decode_hex(text)
    if hex_results:
        for original, decoded in hex_results:
            state.add_insight(f"Decoded hex data: {original[:20]}... -> {decoded[:30]}...", analyzer="crypto_analyzer")
            state.add_transformation(
                name="Hex decode",
                description="Decoded hexadecimal data to plaintext/binary",
                input_data=original,
                output_data=decoded,
                analyzer="crypto_analyzer"
            )

    # Check for blockchain addresses
    blockchain_addresses = identify_blockchain_addresses(text)
    if blockchain_addresses:
        for addr_type, address in blockchain_addresses:
            state.add_insight(f"Identified {addr_type} address: {address}", analyzer="crypto_analyzer")

            # If it's an Ethereum address, try to analyze it using Etherscan
            if addr_type == "Ethereum":
                eth_info = analyze_ethereum_address(address)
                if eth_info:
                    state.add_insight(f"Ethereum address analysis: {eth_info}", analyzer="crypto_analyzer")

    # Check for PGP/GPG signatures or keys
    pgp_elements = identify_pgp_elements(text)
    if pgp_elements:
        for elem_type, content in pgp_elements:
            state.add_insight(f"Identified PGP/GPG {elem_type}: {content[:50]}...", analyzer="crypto_analyzer")

    # Check for cryptocurrency private keys
    private_keys = identify_private_keys(text)
    if private_keys:
        for key_type, key_value in private_keys:
            # Mask the key for security in logs
            masked_key = key_value[:6] + "..." + key_value[-4:] if len(key_value) > 10 else key_value
            state.add_insight(f"Found potential {key_type} private key: {masked_key}", analyzer="crypto_analyzer")
            state.add_transformation(
                name=f"{key_type} private key",
                description=f"Identified {key_type} private key",
                input_data=text,
                output_data=f"Private key found: {masked_key}",
                analyzer="crypto_analyzer"
            )

    # Check for wallet files in JSON format
    wallet_files = identify_wallet_files(text)
    if wallet_files:
        for wallet_type, wallet_content in wallet_files:
            state.add_insight(f"Identified {wallet_type} wallet file", analyzer="crypto_analyzer")

            # Extract wallet address if possible
            wallet_address = extract_wallet_address(wallet_type, wallet_content)
            if wallet_address:
                state.add_insight(f"Extracted wallet address from {wallet_type} wallet: {wallet_address}", analyzer="crypto_analyzer")

                # If it's an Ethereum wallet, try to analyze the address
                if wallet_type == "Ethereum":
                    eth_info = analyze_ethereum_address(wallet_address)
                    if eth_info:
                        state.add_insight(f"Ethereum wallet analysis: {eth_info}", analyzer="crypto_analyzer")

    # Check for smart contract code
    contract_code = identify_smart_contracts(text)
    if contract_code:
        for contract_type, code in contract_code:
            state.add_insight(f"Identified {contract_type} smart contract code", analyzer="crypto_analyzer")

            # Basic analysis of the contract
            contract_analysis = analyze_smart_contract(contract_type, code)
            if contract_analysis:
                state.add_insight(f"Smart contract analysis: {contract_analysis}", analyzer="crypto_analyzer")

    # If we have binary data, perform additional analysis
    if state.binary_data:
        # Check for wallet files
        state.add_insight("Checking binary data for wallet files...", analyzer="crypto_analyzer")
        binary_wallet_results = analyze_binary_for_wallets(state.binary_data)
        if binary_wallet_results:
            for wallet_type, wallet_info in binary_wallet_results:
                state.add_insight(f"Found {wallet_type} wallet in binary data: {wallet_info}", analyzer="crypto_analyzer")

        # Check if the binary data is an image
        is_image = False
        image_type = None

        # Check common image signatures
        if state.binary_data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
            is_image = True
            image_type = "png"
        elif state.binary_data[:2] == b'\xff\xd8':
            is_image = True
            image_type = "jpeg"
        elif state.binary_data[:3] == b'GIF':
            is_image = True
            image_type = "gif"
        elif state.binary_data[:2] == b'BM':
            is_image = True
            image_type = "bmp"

        if is_image:
            state.add_insight(f"Binary data appears to be a {image_type.upper()} image, performing steganography analysis...", analyzer="crypto_analyzer")

            # Run comprehensive steganography analysis
            stego_results = analyze_stego(state.binary_data, file_type=image_type)

            if stego_results["success"]:
                # Check for LSB steganography results
                if "lsb" in stego_results["analysis_results"] and stego_results["analysis_results"]["lsb"]["success"]:
                    lsb_data = stego_results["analysis_results"]["lsb"]
                    if "possible_text" in lsb_data and lsb_data["possible_text"]:
                        state.add_insight(f"Found potential hidden text in LSB data: {lsb_data['possible_text'][:100]}...", analyzer="crypto_analyzer")
                        state.add_transformation(
                            name="LSB Steganography",
                            description="Text extracted from least significant bits",
                            input_data=f"{image_type.upper()} image",
                            output_data=lsb_data['possible_text'],
                            analyzer="crypto_analyzer"
                        )

                # Check for appended data
                if "appended_data" in stego_results["analysis_results"] and stego_results["analysis_results"]["appended_data"]["has_appended_data"]:
                    appended_data = stego_results["analysis_results"]["appended_data"]
                    state.add_insight(f"Found data appended after the {image_type.upper()} file: {appended_data['appended_data_size']} bytes", analyzer="crypto_analyzer")

                    if "appended_text" in appended_data:
                        state.add_insight(f"Appended data as text: {appended_data['appended_text'][:100]}...", analyzer="crypto_analyzer")
                        state.add_transformation(
                            name="Appended Data",
                            description=f"Data appended after {image_type.upper()} file",
                            input_data=f"{image_type.upper()} image",
                            output_data=appended_data['appended_text'],
                            analyzer="crypto_analyzer"
                        )

                # Check for embedded files
                if "embedded_files" in stego_results["analysis_results"] and stego_results["analysis_results"]["embedded_files"]["success"]:
                    embedded_files = stego_results["analysis_results"]["embedded_files"]
                    if embedded_files["embedded_files"]:
                        state.add_insight(f"Found {len(embedded_files['embedded_files'])} potential embedded files in the image", analyzer="crypto_analyzer")

                        for embedded_file in embedded_files["embedded_files"][:3]:  # Limit to first 3
                            state.add_insight(f"Potential {embedded_file['file_type']} at offset {embedded_file['offset']}", analyzer="crypto_analyzer")

                # Check for zsteg results (PNG and BMP only)
                if image_type in ["png", "bmp"] and "zsteg" in stego_results["analysis_results"]:
                    zsteg_results = stego_results["analysis_results"]["zsteg"]
                    if zsteg_results["success"] and zsteg_results["findings"]:
                        state.add_insight(f"zsteg found {len(zsteg_results['findings'])} potential hidden data in the image", analyzer="crypto_analyzer")

                        for finding in zsteg_results["findings"][:5]:  # Limit to first 5
                            state.add_insight(f"zsteg found: {finding['type']} - {finding['content'][:100]}", analyzer="crypto_analyzer")
                            state.add_transformation(
                                name=f"zsteg: {finding['type']}",
                                description=f"Hidden data found by zsteg in {finding['type']}",
                                input_data=f"{image_type.upper()} image",
                                output_data=finding['content'],
                                analyzer="crypto_analyzer"
                            )
                    elif "error" in zsteg_results:
                        state.add_insight(f"zsteg analysis failed: {zsteg_results['error']}", analyzer="crypto_analyzer")

                # Check for binwalk results
                if "binwalk" in stego_results["analysis_results"]:
                    binwalk_results = stego_results["analysis_results"]["binwalk"]
                    if binwalk_results["success"]:
                        if binwalk_results["signatures"]:
                            state.add_insight(f"binwalk found {len(binwalk_results['signatures'])} file signatures in the image", analyzer="crypto_analyzer")

                            for signature in binwalk_results["signatures"][:3]:  # Limit to first 3
                                state.add_insight(f"binwalk signature at offset {signature['offset']}: {signature['description']}", analyzer="crypto_analyzer")

                        if binwalk_results["extracted_files"]:
                            state.add_insight(f"binwalk extracted {len(binwalk_results['extracted_files'])} files from the image", analyzer="crypto_analyzer")

                            for extracted_file in binwalk_results["extracted_files"][:2]:  # Limit to first 2
                                state.add_insight(f"binwalk extracted: {extracted_file['name']} ({extracted_file['size']} bytes)", analyzer="crypto_analyzer")
                                state.add_transformation(
                                    name=f"binwalk: {extracted_file['name']}",
                                    description=f"File extracted by binwalk from image",
                                    input_data=f"{image_type.upper()} image",
                                    output_data=f"First 100 bytes (hex): {extracted_file['data'][:100].hex()}",
                                    analyzer="crypto_analyzer"
                                )
                    elif "error" in binwalk_results:
                        state.add_insight(f"binwalk analysis failed: {binwalk_results['error']}", analyzer="crypto_analyzer")
            else:
                if "error" in stego_results:
                    state.add_insight(f"Steganography analysis failed: {stego_results['error']}", analyzer="crypto_analyzer")
        else:
            # For non-image binary data, still run binwalk
            state.add_insight("Running binwalk on binary data to check for embedded files...", analyzer="crypto_analyzer")
            binwalk_results = run_binwalk(state.binary_data)

            if binwalk_results["success"]:
                if binwalk_results["signatures"]:
                    state.add_insight(f"binwalk found {len(binwalk_results['signatures'])} file signatures in the binary data", analyzer="crypto_analyzer")

                    for signature in binwalk_results["signatures"][:3]:  # Limit to first 3
                        state.add_insight(f"binwalk signature at offset {signature['offset']}: {signature['description']}", analyzer="crypto_analyzer")

                if binwalk_results["extracted_files"]:
                    state.add_insight(f"binwalk extracted {len(binwalk_results['extracted_files'])} files from the binary data", analyzer="crypto_analyzer")

                    for extracted_file in binwalk_results["extracted_files"][:2]:  # Limit to first 2
                        state.add_insight(f"binwalk extracted: {extracted_file['name']} ({extracted_file['size']} bytes)", analyzer="crypto_analyzer")
                        state.add_transformation(
                            name=f"binwalk: {extracted_file['name']}",
                            description=f"File extracted by binwalk from binary data",
                            input_data="Binary data",
                            output_data=f"First 100 bytes (hex): {extracted_file['data'][:100].hex()}",
                            analyzer="crypto_analyzer"
                        )
            elif "error" in binwalk_results:
                state.add_insight(f"binwalk analysis failed: {binwalk_results['error']}", analyzer="crypto_analyzer")

    return state

def identify_hashes(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential cryptographic hashes in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (hash_type, hash_value) tuples
    """
    results = []

    # Define regex patterns for common hash formats
    hash_patterns = {
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "SHA256": r"\b[a-fA-F0-9]{64}\b",
        "SHA512": r"\b[a-fA-F0-9]{128}\b"
    }

    # Search for each hash pattern
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Verify it's not just a random hex string by checking entropy
            if is_likely_hash(match):
                results.append((hash_type, match))

    return results

def is_likely_hash(hex_string: str) -> bool:
    """
    Check if a hex string is likely to be a hash by analyzing its entropy.

    Args:
        hex_string: Hexadecimal string to check

    Returns:
        True if the string is likely a hash, False otherwise
    """
    # Simple entropy check - real hashes have fairly uniform distribution
    char_counts = {}
    for char in hex_string.lower():
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate normalized entropy
    entropy = 0
    length = len(hex_string)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * (probability.bit_length() if probability > 0 else 0)

    # Higher entropy suggests more randomness, typical of hashes
    return entropy > 0.6

def attempt_hash_crack(hash_value: str, hash_type: str) -> Optional[str]:
    """
    Attempt to crack a hash using a small dictionary of common values.

    Args:
        hash_value: The hash to crack
        hash_type: Type of hash (MD5, SHA1, SHA256)

    Returns:
        Cracked plaintext if successful, None otherwise
    """
    # Common passwords and phrases to try
    common_values = [
        "password", "123456", "admin", "welcome", "secret",
        "letmein", "monkey", "1234567890", "qwerty",
        "abc123", "password123", "admin123", "test",
        "cryptopuzzle", "hunter", "puzzle", "crypto",
        "flag", "key", "solution", "answer", "treasure",
        "bitcoin", "ethereum", "blockchain", "satoshi"
    ]

    hash_function = None
    if hash_type == "MD5":
        hash_function = lambda x: hashlib.md5(x.encode()).hexdigest()
    elif hash_type == "SHA1":
        hash_function = lambda x: hashlib.sha1(x.encode()).hexdigest()
    elif hash_type == "SHA256":
        hash_function = lambda x: hashlib.sha256(x.encode()).hexdigest()
    else:
        return None

    # Try each common value
    for value in common_values:
        if hash_function(value) == hash_value.lower():
            return value

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

    # Find potential base64 strings (must be at least 16 chars to reduce false positives)
    base64_pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
    matches = re.findall(base64_pattern, text)

    for match in matches:
        try:
            # Try to decode and check if result is printable or looks like binary data
            decoded = base64.b64decode(match).decode('utf-8', errors='replace')
            if any(c.isprintable() for c in decoded):
                results.append((match, decoded))
        except Exception:
            # If decoding as text fails, it might be binary data
            try:
                decoded_bytes = base64.b64decode(match)
                # Convert to hex representation for display
                hex_repr = binascii.hexlify(decoded_bytes).decode('ascii')
                results.append((match, f"[Binary data, hex: {hex_repr[:30]}...]"))
            except Exception:
                # Not valid base64
                pass

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

    # Find potential hex strings (must be even length and at least 8 chars)
    hex_pattern = r'\b(?:[0-9A-Fa-f]{2}){4,}\b'
    matches = re.findall(hex_pattern, text)

    for match in matches:
        if len(match) % 2 == 0:  # Valid hex strings have even length
            try:
                # Try to decode and check if result is printable
                decoded_bytes = binascii.unhexlify(match)
                try:
                    decoded = decoded_bytes.decode('utf-8', errors='replace')
                    if any(c.isprintable() for c in decoded):
                        results.append((match, decoded))
                except UnicodeDecodeError:
                    # If decoding as text fails, it's binary data
                    results.append((match, f"[Binary data, length: {len(decoded_bytes)} bytes]"))
            except binascii.Error:
                # Not valid hex
                pass

    return results

def identify_blockchain_addresses(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential blockchain addresses in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (address_type, address) tuples
    """
    results = []

    # Bitcoin address patterns
    btc_pattern = r'\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b'
    btc_matches = re.findall(btc_pattern, text)
    for match in btc_matches:
        results.append(("Bitcoin", match))

    # Ethereum address pattern
    eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
    eth_matches = re.findall(eth_pattern, text)
    for match in eth_matches:
        results.append(("Ethereum", match))

    return results

def identify_pgp_elements(text: str) -> List[Tuple[str, str]]:
    """
    Identify PGP/GPG elements like signatures, keys, or encrypted messages.

    Args:
        text: Text to analyze

    Returns:
        List of (element_type, content) tuples
    """
    results = []

    # PGP public key block
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text:
        pgp_key_pattern = r'-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----'
        matches = re.findall(pgp_key_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP PUBLIC KEY BLOCK-----{match}-----END PGP PUBLIC KEY BLOCK-----"
            results.append(("public key", full_match))

    # PGP signature
    if "-----BEGIN PGP SIGNATURE-----" in text:
        pgp_sig_pattern = r'-----BEGIN PGP SIGNATURE-----(.*?)-----END PGP SIGNATURE-----'
        matches = re.findall(pgp_sig_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP SIGNATURE-----{match}-----END PGP SIGNATURE-----"
            results.append(("signature", full_match))

    # PGP message
    if "-----BEGIN PGP MESSAGE-----" in text:
        pgp_msg_pattern = r'-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----'
        matches = re.findall(pgp_msg_pattern, text, re.DOTALL)
        for match in matches:
            full_match = f"-----BEGIN PGP MESSAGE-----{match}-----END PGP MESSAGE-----"
            results.append(("encrypted message", full_match))

    return results

def identify_private_keys(text: str) -> List[Tuple[str, str]]:
    """
    Identify potential cryptocurrency private keys in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (key_type, key_value) tuples
    """
    results = []

    # Bitcoin private key formats
    # WIF (Wallet Import Format) - starts with 5, K, or L
    wif_pattern = r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,52}\b'
    wif_matches = re.findall(wif_pattern, text)
    for match in wif_matches:
        results.append(("Bitcoin WIF", match))

    # Bitcoin mini private key format (typically 30 chars)
    mini_key_pattern = r'\bS[1-9A-HJ-NP-Za-km-z]{29}\b'
    mini_matches = re.findall(mini_key_pattern, text)
    for match in mini_matches:
        results.append(("Bitcoin mini key", match))

    # Ethereum private key (64 hex chars)
    eth_key_pattern = r'\b[0-9a-fA-F]{64}\b'
    eth_matches = re.findall(eth_key_pattern, text)
    for match in eth_matches:
        # Verify it's not just a random hex string by checking entropy
        if is_likely_hash(match):
            results.append(("Ethereum", match))

    # BIP39 mnemonic seed phrases (12, 15, 18, 21, or 24 words)
    # Look for sequences of words that might be seed phrases
    # This is a simplified approach - in a real implementation, we would check against the full BIP39 wordlist
    word_pattern = r'\b[a-z]{3,8}\b'
    words = re.findall(word_pattern, text.lower())

    # Check for sequences of words that might be seed phrases
    if len(words) >= 12:
        # Look for sequences of 12, 15, 18, 21, or 24 words
        for phrase_length in [12, 15, 18, 21, 24]:
            if len(words) >= phrase_length:
                for i in range(len(words) - phrase_length + 1):
                    phrase = " ".join(words[i:i+phrase_length])
                    # Check if the phrase looks like a BIP39 mnemonic
                    if is_likely_mnemonic(phrase):
                        results.append(("BIP39 mnemonic", phrase))

    return results

def is_likely_mnemonic(phrase: str) -> bool:
    """
    Check if a phrase is likely to be a BIP39 mnemonic seed phrase.

    Args:
        phrase: The phrase to check

    Returns:
        True if the phrase is likely a mnemonic, False otherwise
    """
    # Common BIP39 words (partial list of most common words)
    common_bip39_words = {
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", 
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", 
        "acoustic", "acquire", "across", "act", "action", "actor", "address", "adjust", 
        "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", 
        "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", 
        "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", 
        "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", 
        "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", 
        "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", 
        "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", 
        "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", 
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artist", 
        "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", 
        "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", 
        "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", 
        "awake", "aware", "away", "awesome", "awful", "awkward", "axis"
    }

    # Split the phrase into words
    words = phrase.lower().split()

    # Count how many words are in our common BIP39 word list
    bip39_word_count = sum(1 for word in words if word in common_bip39_words)

    # If more than 70% of the words are in our common BIP39 word list, it's likely a mnemonic
    return bip39_word_count / len(words) > 0.7

def identify_wallet_files(text: str) -> List[Tuple[str, str]]:
    """
    Identify cryptocurrency wallet files in JSON format.

    Args:
        text: Text to analyze

    Returns:
        List of (wallet_type, wallet_content) tuples
    """
    results = []

    # Try to find JSON objects in the text
    json_pattern = r'(\{[^{}]*\{[^{}]*\}[^{}]*\}|\{[^{}]*\})'
    json_matches = re.findall(json_pattern, text)

    for json_str in json_matches:
        try:
            # Try to parse as JSON
            json_obj = json.loads(json_str)

            # Check for Ethereum keystore file (UTC--*)
            if isinstance(json_obj, dict) and all(k in json_obj for k in ["version", "crypto", "id"]):
                if "crypto" in json_obj and isinstance(json_obj["crypto"], dict):
                    if "ciphertext" in json_obj["crypto"] and "cipher" in json_obj["crypto"]:
                        results.append(("Ethereum keystore", json_str))
                        continue

            # Check for Ethereum web3 wallet
            if isinstance(json_obj, dict) and "address" in json_obj and "crypto" in json_obj:
                results.append(("Ethereum web3", json_str))
                continue

            # Check for Bitcoin wallet export (from various wallets)
            if isinstance(json_obj, dict) and "keys" in json_obj:
                if isinstance(json_obj["keys"], list) or isinstance(json_obj["keys"], dict):
                    results.append(("Bitcoin wallet export", json_str))
                    continue

            # Check for MetaMask vault
            if isinstance(json_obj, dict) and "vault" in json_obj:
                results.append(("MetaMask vault", json_str))
                continue

            # Check for generic wallet backup with addresses
            if isinstance(json_obj, dict) and ("addresses" in json_obj or "accounts" in json_obj):
                results.append(("Generic wallet backup", json_str))
                continue

        except json.JSONDecodeError:
            # Not valid JSON
            pass

    return results

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
        # Parse the wallet content as JSON
        wallet_json = json.loads(wallet_content)

        # Extract address based on wallet type
        if wallet_type == "Ethereum keystore":
            # Try to extract the address from the filename pattern in the id field
            if "id" in wallet_json:
                # Some keystores include the address in the UUID
                uuid_str = wallet_json["id"]
                if isinstance(uuid_str, str) and len(uuid_str) > 8:
                    # Check if there's a pattern like 0x... in the UUID
                    addr_match = re.search(r'(0x[a-fA-F0-9]{40})', uuid_str)
                    if addr_match:
                        return addr_match.group(1)

            # Try to extract from the address field
            if "address" in wallet_json:
                addr = wallet_json["address"]
                # Add 0x prefix if missing
                if isinstance(addr, str) and len(addr) == 40:
                    return f"0x{addr}"
                elif isinstance(addr, str) and len(addr) == 42 and addr.startswith("0x"):
                    return addr

        elif wallet_type == "Ethereum web3":
            if "address" in wallet_json:
                addr = wallet_json["address"]
                # Add 0x prefix if missing
                if isinstance(addr, str) and len(addr) == 40:
                    return f"0x{addr}"
                elif isinstance(addr, str) and len(addr) == 42 and addr.startswith("0x"):
                    return addr

        elif wallet_type == "Bitcoin wallet export":
            # Different wallet exports have different formats
            if "keys" in wallet_json and isinstance(wallet_json["keys"], list):
                for key in wallet_json["keys"]:
                    if isinstance(key, dict) and "addr" in key:
                        return key["addr"]

            # Try to find any field that looks like a Bitcoin address
            for key, value in wallet_json.items():
                if key.lower() in ["address", "addr", "bitcoin_address", "receiving_address"]:
                    if isinstance(value, str) and re.match(r'^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}$', value):
                        return value

        elif wallet_type == "MetaMask vault":
            if "vault" in wallet_json:
                # MetaMask vaults are encrypted, but sometimes contain address hints
                vault_str = str(wallet_json["vault"])
                addr_match = re.search(r'(0x[a-fA-F0-9]{40})', vault_str)
                if addr_match:
                    return addr_match.group(1)

        elif wallet_type == "Generic wallet backup":
            # Try to find addresses in common fields
            for field in ["addresses", "accounts"]:
                if field in wallet_json:
                    addresses = wallet_json[field]
                    if isinstance(addresses, list) and len(addresses) > 0:
                        # Return the first address
                        if isinstance(addresses[0], str):
                            return addresses[0]
                        elif isinstance(addresses[0], dict) and "address" in addresses[0]:
                            return addresses[0]["address"]

            # Try to find any field that looks like an address
            for key, value in wallet_json.items():
                if key.lower() in ["address", "addr", "account", "wallet_address"]:
                    if isinstance(value, str):
                        # Check if it looks like an Ethereum address
                        if re.match(r'^0x[a-fA-F0-9]{40}$', value):
                            return value
                        # Check if it looks like a Bitcoin address
                        elif re.match(r'^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}$', value):
                            return value

    except (json.JSONDecodeError, KeyError, TypeError):
        # Error parsing JSON or accessing fields
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
    results = []

    # Try to decode as UTF-8 and look for wallet patterns
    try:
        text = binary_data.decode('utf-8', errors='replace')

        # Look for wallet files in the decoded text
        wallet_files = identify_wallet_files(text)
        if wallet_files:
            for wallet_type, wallet_content in wallet_files:
                # Extract wallet address if possible
                wallet_address = extract_wallet_address(wallet_type, wallet_content)
                if wallet_address:
                    results.append((wallet_type, f"Address: {wallet_address}"))
                else:
                    results.append((wallet_type, "Address not found"))
    except UnicodeDecodeError:
        pass

    # Check for wallet file signatures in binary
    # Ethereum keystore files often start with '{"version":3'
    if b'{"version":3' in binary_data:
        results.append(("Ethereum keystore", "Found keystore signature in binary data"))

    # Bitcoin wallet.dat files have a specific header
    if b'\xf9\xbe\xb4\xd9' in binary_data:
        results.append(("Bitcoin wallet.dat", "Found wallet.dat signature in binary data"))

    return results

def analyze_ethereum_address(address: str) -> Optional[str]:
    """
    Analyze an Ethereum address using Etherscan API.

    Args:
        address: Ethereum address to analyze

    Returns:
        Analysis results as a string, or None if analysis failed
    """
    # Get Etherscan API key from environment variables
    api_key = os.environ.get("ETHERSCAN_API_KEY")
    if not api_key:
        return "Etherscan API key not found in environment variables"

    # Normalize the address
    if not address.startswith("0x"):
        address = f"0x{address}"

    # Validate the address format
    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        return None

    try:
        # Get basic account information
        account_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
        account_response = requests.get(account_url, timeout=5)
        account_data = account_response.json()

        if account_data.get("status") != "1":
            return f"Error from Etherscan API: {account_data.get('message', 'Unknown error')}"

        # Convert wei to ether
        balance_wei = int(account_data.get("result", "0"))
        balance_eth = balance_wei / 1e18

        # Get transaction count
        txcount_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest&apikey={api_key}"
        txcount_response = requests.get(txcount_url, timeout=5)
        txcount_data = txcount_response.json()

        tx_count = int(txcount_data.get("result", "0x0"), 16) if "result" in txcount_data else 0

        # Check if it's a contract
        code_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={address}&tag=latest&apikey={api_key}"
        code_response = requests.get(code_url, timeout=5)
        code_data = code_response.json()

        is_contract = code_data.get("result", "0x") != "0x"

        # Build the result string
        result = f"Balance: {balance_eth:.6f} ETH, Transactions: {tx_count}"
        if is_contract:
            result += ", Type: Smart Contract"

            # Get contract info if it's verified
            contract_url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}"
            contract_response = requests.get(contract_url, timeout=5)
            contract_data = contract_response.json()

            if contract_data.get("status") == "1" and contract_data.get("result"):
                contract_info = contract_data["result"][0]
                contract_name = contract_info.get("ContractName", "Unknown")
                if contract_name != "":
                    result += f", Name: {contract_name}"
        else:
            result += ", Type: EOA (Externally Owned Account)"

        return result

    except requests.RequestException as e:
        return f"Error connecting to Etherscan API: {str(e)}"
    except (ValueError, KeyError, TypeError) as e:
        return f"Error processing Etherscan API response: {str(e)}"

def identify_smart_contracts(text: str) -> List[Tuple[str, str]]:
    """
    Identify smart contract code in the text.

    Args:
        text: Text to analyze

    Returns:
        List of (contract_type, code) tuples
    """
    results = []

    # Check for Solidity contracts
    if "contract " in text and "function " in text:
        # Look for Solidity contract definitions
        solidity_pattern = r'(contract\s+\w+\s*\{[^}]*\})'
        solidity_matches = re.findall(solidity_pattern, text, re.DOTALL)

        for match in solidity_matches:
            # Verify it's likely Solidity code
            if "function" in match and ("public" in match or "private" in match or "internal" in match):
                results.append(("Solidity", match))

    # Check for Vyper contracts
    if "@public" in text or "@external" in text:
        # Look for Vyper contract structure
        if "def " in text and ":" in text:
            # Extract the whole potential Vyper contract
            vyper_lines = []
            in_contract = False

            for line in text.split('\n'):
                if "@" in line and "def " in line:
                    in_contract = True
                    vyper_lines.append(line)
                elif in_contract and line.strip():
                    vyper_lines.append(line)

            if vyper_lines:
                vyper_code = '\n'.join(vyper_lines)
                results.append(("Vyper", vyper_code))

    return results

def analyze_smart_contract(contract_type: str, code: str) -> Optional[str]:
    """
    Perform basic analysis of smart contract code.

    Args:
        contract_type: Type of contract (Solidity, Vyper)
        code: Contract code

    Returns:
        Analysis results as a string, or None if analysis failed
    """
    if contract_type == "Solidity":
        # Extract contract name
        name_match = re.search(r'contract\s+(\w+)', code)
        contract_name = name_match.group(1) if name_match else "Unknown"

        # Count functions
        function_count = len(re.findall(r'function\s+\w+', code))

        # Check for common vulnerabilities
        vulnerabilities = []

        if "selfdestruct" in code or "suicide" in code:
            vulnerabilities.append("Self-destruct capability")

        if "tx.origin" in code:
            vulnerabilities.append("tx.origin usage (potential phishing vulnerability)")

        if "block.timestamp" in code or "now" in code:
            vulnerabilities.append("Timestamp dependency")

        if ".call{value:" in code or ".call.value(" in code:
            vulnerabilities.append("Low-level call with value (potential reentrancy)")

        if "assembly" in code:
            vulnerabilities.append("Assembly usage (potential for dangerous operations)")

        # Build result string
        result = f"Solidity contract '{contract_name}' with {function_count} functions"

        if vulnerabilities:
            result += f". Potential issues: {', '.join(vulnerabilities)}"

        return result

    elif contract_type == "Vyper":
        # Count functions
        public_functions = len(re.findall(r'@public', code))
        external_functions = len(re.findall(r'@external', code))

        # Check for common patterns
        has_erc20 = "balanceOf" in code and "transfer" in code and "allowance" in code
        has_erc721 = "ownerOf" in code and "transferFrom" in code and "safeTransferFrom" in code

        # Build result string
        result = f"Vyper contract with {public_functions} public and {external_functions} external functions"

        if has_erc20:
            result += ". Appears to be an ERC-20 token contract"
        elif has_erc721:
            result += ". Appears to be an ERC-721 NFT contract"

        return result

    return None
