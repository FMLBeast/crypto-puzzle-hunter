"""
Web Agent Module
Handles web-based analysis and external API calls for crypto puzzles.
"""

import logging
import re
import json
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

class WebAgent:
    """
    Agent responsible for web-based analysis and external API calls.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.name = "WebAgent"
        logger.debug("WebAgent initialized")

    def run(self, state):
        try:
            if self.verbose:
                logger.info("🔍 Running web analysis...")

            findings_count = 0

            # Collect URLs and addresses from all sources
            urls = []
            crypto_addresses = []

            # Extract URLs and addresses from materials
            for material_id, material in state.materials.items():
                material_urls, material_addresses = self._extract_web_data(material)
                urls.extend(material_urls)
                crypto_addresses.extend(material_addresses)

            # Extract from existing findings
            for finding in state.findings:
                finding_urls, finding_addresses = self._extract_from_text(finding.description)
                urls.extend(finding_urls)
                crypto_addresses.extend(finding_addresses)

            # Analyze found URLs
            if urls:
                findings_count += self._analyze_urls(state, urls)

            # Analyze crypto addresses (prepare for web lookups)
            if crypto_addresses:
                findings_count += self._analyze_crypto_addresses(state, crypto_addresses)

            # Look for blockchain explorer patterns
            findings_count += self._find_blockchain_patterns(state)

            logger.info(f"Web analysis completed - found {findings_count} insights")
            return state

        except Exception as e:
            logger.error(f"Error in WebAgent.run: {e}")
            return state

    def _extract_web_data(self, material):
        """Extract URLs and crypto addresses from material."""
        urls = []
        addresses = []

        try:
            content = material.content

            # Convert to text for analysis
            if isinstance(content, bytes):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except:
                    text_content = content.decode('latin-1', errors='ignore')
            else:
                text_content = str(content)

            # Extract URLs and addresses
            material_urls, material_addresses = self._extract_from_text(text_content)
            urls.extend(material_urls)
            addresses.extend(material_addresses)

        except Exception as e:
            logger.error(f"Error extracting web data from {material.name}: {e}")

        return urls, addresses

    def _extract_from_text(self, text):
        """Extract URLs and crypto addresses from text."""
        urls = []
        addresses = []

        try:
            # Extract URLs
            url_patterns = [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                r'www\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}[^\s<>"{}|\\^`\[\]]*',
                r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.(?:com|org|net|io|co)[^\s<>"{}|\\^`\[\]]*'
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                urls.extend(matches)

            # Extract crypto addresses
            # Bitcoin addresses
            btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            btc_matches = re.findall(btc_pattern, text)
            addresses.extend([('bitcoin', addr) for addr in btc_matches])

            # Bitcoin Bech32
            bech32_pattern = r'\bbc1[a-z0-9]{39,59}\b'
            bech32_matches = re.findall(bech32_pattern, text, re.IGNORECASE)
            addresses.extend([('bitcoin_bech32', addr) for addr in bech32_matches])

            # Ethereum addresses
            eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
            eth_matches = re.findall(eth_pattern, text)
            addresses.extend([('ethereum', addr) for addr in eth_matches])

        except Exception as e:
            logger.error(f"Error extracting from text: {e}")

        return urls, addresses

    def _analyze_urls(self, state, urls):
        """Analyze found URLs for relevance to crypto puzzles."""
        findings_count = 0

        try:
            unique_urls = list(set(urls))

            if unique_urls:
                state.add_insight(f"Found {len(unique_urls)} unique URLs", "web_agent")
                findings_count += 1

                # Categorize URLs
                blockchain_urls = []
                crypto_urls = []
                suspicious_urls = []
                github_urls = []

                for url in unique_urls:
                    url_lower = url.lower()

                    # Blockchain explorers
                    if any(domain in url_lower for domain in ['blockchain.info', 'blockchair.com', 'etherscan.io', 'btc.com']):
                        blockchain_urls.append(url)

                    # Crypto-related domains
                    elif any(keyword in url_lower for keyword in ['bitcoin', 'crypto', 'blockchain', 'wallet', 'exchange']):
                        crypto_urls.append(url)

                    # GitHub repositories (might contain code/keys)
                    elif 'github.com' in url_lower:
                        github_urls.append(url)

                    # Suspicious patterns (short URLs, unusual domains)
                    elif any(domain in url_lower for domain in ['bit.ly', 'tinyurl', 'pastebin', 'hastebin']):
                        suspicious_urls.append(url)

                # Report categorized URLs
                if blockchain_urls:
                    state.add_insight(f"Found {len(blockchain_urls)} blockchain explorer URLs", "web_agent")
                    findings_count += 1
                    for url in blockchain_urls[:3]:  # First 3
                        findings_count += self._analyze_blockchain_url(state, url)

                if crypto_urls:
                    state.add_insight(f"Found {len(crypto_urls)} crypto-related URLs", "web_agent")
                    findings_count += 1
                    for url in crypto_urls[:3]:
                        state.add_insight(f"Crypto URL: {url}", "web_agent")
                        findings_count += 1

                if github_urls:
                    state.add_insight(f"Found {len(github_urls)} GitHub URLs", "web_agent")
                    findings_count += 1
                    for url in github_urls[:3]:
                        findings_count += self._analyze_github_url(state, url)

                if suspicious_urls:
                    state.add_insight(f"Found {len(suspicious_urls)} potentially interesting URLs", "web_agent")
                    findings_count += 1
                    for url in suspicious_urls[:3]:
                        state.add_insight(f"Interesting URL: {url}", "web_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing URLs: {e}")

        return findings_count

    def _analyze_blockchain_url(self, state, url):
        """Analyze blockchain explorer URLs."""
        findings_count = 0

        try:
            parsed_url = urlparse(url)

            # Extract information from blockchain explorer URLs
            if 'blockchain.info' in parsed_url.hostname:
                # Bitcoin blockchain.info URLs
                if '/address/' in parsed_url.path:
                    address = parsed_url.path.split('/address/')[-1].split('/')[0]
                    state.add_insight(f"Bitcoin address from URL: {address}", "web_agent")
                    findings_count += 1
                elif '/tx/' in parsed_url.path:
                    tx_hash = parsed_url.path.split('/tx/')[-1].split('/')[0]
                    state.add_insight(f"Bitcoin transaction from URL: {tx_hash[:16]}...", "web_agent")
                    findings_count += 1

            elif 'etherscan.io' in parsed_url.hostname:
                # Ethereum etherscan URLs
                if '/address/' in parsed_url.path:
                    address = parsed_url.path.split('/address/')[-1].split('/')[0]
                    state.add_insight(f"Ethereum address from URL: {address}", "web_agent")
                    findings_count += 1
                elif '/tx/' in parsed_url.path:
                    tx_hash = parsed_url.path.split('/tx/')[-1].split('/')[0]
                    state.add_insight(f"Ethereum transaction from URL: {tx_hash[:16]}...", "web_agent")
                    findings_count += 1

            elif 'blockchair.com' in parsed_url.hostname:
                # Multi-blockchain explorer
                path_parts = parsed_url.path.split('/')
                if len(path_parts) >= 3:
                    blockchain = path_parts[1]
                    if 'address' in path_parts:
                        idx = path_parts.index('address')
                        if idx + 1 < len(path_parts):
                            address = path_parts[idx + 1]
                            state.add_insight(f"{blockchain.title()} address from Blockchair: {address}", "web_agent")
                            findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing blockchain URL: {e}")

        return findings_count

    def _analyze_github_url(self, state, url):
        """Analyze GitHub URLs for relevant repositories."""
        findings_count = 0

        try:
            parsed_url = urlparse(url)
            path_parts = parsed_url.path.strip('/').split('/')

            if len(path_parts) >= 2:
                user = path_parts[0]
                repo = path_parts[1]

                # Check if repository name suggests crypto content
                crypto_keywords = ['bitcoin', 'crypto', 'blockchain', 'wallet', 'ethereum', 'puzzle', 'ctf']
                if any(keyword in repo.lower() for keyword in crypto_keywords):
                    state.add_insight(f"GitHub crypto repo: {user}/{repo}", "web_agent")
                    findings_count += 1

                # Check for specific file references
                if len(path_parts) > 4 and path_parts[2] == 'blob':
                    filename = path_parts[-1]
                    if any(ext in filename.lower() for ext in ['.py', '.js', '.sh', '.md', '.txt']):
                        state.add_insight(f"GitHub file reference: {filename}", "web_agent")
                        findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing GitHub URL: {e}")

        return findings_count

    def _analyze_crypto_addresses(self, state, addresses):
        """Analyze crypto addresses for web lookup potential."""
        findings_count = 0

        try:
            # Group by type
            address_types = {}
            for addr_type, addr in addresses:
                if addr_type not in address_types:
                    address_types[addr_type] = []
                address_types[addr_type].append(addr)

            for addr_type, addr_list in address_types.items():
                unique_addresses = list(set(addr_list))

                if unique_addresses:
                    state.add_insight(f"Can lookup {len(unique_addresses)} {addr_type} addresses online", "web_agent")
                    findings_count += 1

                    # Generate lookup suggestions
                    for address in unique_addresses[:3]:  # First 3
                        lookup_url = self._generate_lookup_url(addr_type, address)
                        if lookup_url:
                            state.add_insight(f"Lookup URL for {address[:10]}...: {lookup_url}", "web_agent")
                            findings_count += 1

        except Exception as e:
            logger.error(f"Error analyzing crypto addresses: {e}")

        return findings_count

    def _generate_lookup_url(self, addr_type, address):
        """Generate blockchain explorer URL for address lookup."""
        try:
            if addr_type in ['bitcoin', 'bitcoin_bech32']:
                return f"https://blockchain.info/address/{address}"
            elif addr_type == 'ethereum':
                return f"https://etherscan.io/address/{address}"
            elif addr_type == 'litecoin':
                return f"https://blockchair.com/litecoin/address/{address}"
        except Exception as e:
            logger.error(f"Error generating lookup URL: {e}")

        return None

    def _find_blockchain_patterns(self, state):
        """Find patterns that suggest blockchain interaction."""
        findings_count = 0

        try:
            # Look through all findings for blockchain-related patterns
            blockchain_keywords = [
                'transaction', 'block', 'hash', 'merkle', 'nonce', 'difficulty',
                'mining', 'stake', 'validator', 'smart contract', 'gas', 'wei'
            ]

            api_patterns = [
                r'api\.blockchain\.info',
                r'etherscan\.io/api',
                r'blockchair\.com/api',
                r'api\.blockcy\.com'
            ]

            for finding in state.findings:
                text = finding.description.lower()

                # Check for blockchain keywords
                found_keywords = [kw for kw in blockchain_keywords if kw in text]
                if found_keywords:
                    state.add_insight(f"Finding contains blockchain terms: {', '.join(found_keywords[:3])}", "web_agent")
                    findings_count += 1

                # Check for API patterns
                for pattern in api_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        state.add_insight(f"Found blockchain API reference: {pattern}", "web_agent")
                        findings_count += 1
                        break

        except Exception as e:
            logger.error(f"Error finding blockchain patterns: {e}")

        return findings_count

    def _simulate_web_lookup(self, state, address_type, address):
        """Simulate a web lookup for demonstration (placeholder)."""
        findings_count = 0

        try:
            # In a real implementation, this would make actual HTTP requests
            # For now, simulate the types of information that might be found

            if address_type == 'bitcoin':
                state.add_insight(f"Simulated Bitcoin lookup for {address[:10]}... - would check balance/transactions", "web_agent")
                findings_count += 1

            elif address_type == 'ethereum':
                state.add_insight(f"Simulated Ethereum lookup for {address[:10]}... - would check balance/contract", "web_agent")
                findings_count += 1

        except Exception as e:
            logger.error(f"Error in simulated web lookup: {e}")

        return findings_count

    def _validate_url(self, url):
        """Validate if URL is properly formatted."""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.scheme in ['http', 'https'])
        except:
            return False

    def _extract_domain_info(self, url):
        """Extract useful information from URL domain."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check for known crypto-related domains
            crypto_domains = [
                'blockchain.info', 'etherscan.io', 'btc.com', 'blockchair.com',
                'coinbase.com', 'binance.com', 'kraken.com', 'bitfinex.com'
            ]

            for crypto_domain in crypto_domains:
                if crypto_domain in domain:
                    return f"crypto_service_{crypto_domain.split('.')[0]}"

            # Check for other interesting domains
            if 'github.com' in domain:
                return 'code_repository'
            elif 'pastebin.com' in domain or 'hastebin.com' in domain:
                return 'text_sharing'
            elif any(tld in domain for tld in ['.onion', '.i2p']):
                return 'darknet'

            return 'unknown'

        except Exception as e:
            logger.error(f"Error extracting domain info: {e}")
            return 'error'