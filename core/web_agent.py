"""
Web browsing agent for Crypto Hunter.
Allows the agent to search the web and analyze online information.
"""

import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Any, Optional, Union
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebAgent:
    """
    Agent capable of browsing the web to gather information for puzzle solving.
    """
    def __init__(self, 
                 user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                 rate_limit=2,  # seconds between requests
                 max_pages=10,
                 timeout=10,
                 proxies=None):
        """
        Initialize the WebAgent.
        
        Args:
            user_agent: Browser user agent string
            rate_limit: Time in seconds between requests
            max_pages: Maximum number of pages to visit
            timeout: Request timeout in seconds
            proxies: Optional proxy configuration
        """
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.max_pages = max_pages
        self.timeout = timeout
        self.proxies = proxies
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.last_request_time = 0
        self.visited_urls = set()
        
    def fetch_url(self, url: str) -> Optional[str]:
        """
        Fetch the content of a URL.
        
        Args:
            url: URL to fetch
            
        Returns:
            HTML content or None if failed
        """
        # Respect rate limiting
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        
        try:
            self.last_request_time = time.time()
            response = self.session.get(
                url, 
                timeout=self.timeout,
                proxies=self.proxies
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
    
    def search(self, query: str, search_engine="https://duckduckgo.com/html/", 
               num_results=5) -> List[Dict[str, str]]:
        """
        Perform a web search.
        
        Args:
            query: Search query
            search_engine: Search engine URL
            num_results: Maximum number of results to return
            
        Returns:
            List of search results (title, url, snippet)
        """
        try:
            params = {"q": query}
            
            # Respect rate limiting
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            
            self.last_request_time = time.time()
            response = self.session.get(
                search_engine, 
                params=params,
                timeout=self.timeout,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            # Parse the search results
            soup = BeautifulSoup(response.text, "html.parser")
            results = []
            
            # DuckDuckGo specific parsing
            for result in soup.select(".result"):
                title_elem = result.select_one(".result__title")
                url_elem = result.select_one(".result__url")
                snippet_elem = result.select_one(".result__snippet")
                
                if title_elem and url_elem:
                    title = title_elem.get_text(strip=True)
                    url = url_elem.get("href") if url_elem.get("href") else url_elem.get_text(strip=True)
                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""
                    
                    results.append({
                        "title": title,
                        "url": url,
                        "snippet": snippet
                    })
                    
                    if len(results) >= num_results:
                        break
            
            return results
        
        except Exception as e:
            logger.error(f"Error searching for '{query}': {e}")
            return []
    
    def extract_text(self, html: str) -> str:
        """
        Extract readable text from HTML.
        
        Args:
            html: HTML content
            
        Returns:
            Extracted text
        """
        if not html:
            return ""
        
        soup = BeautifulSoup(html, "html.parser")
        
        # Remove script and style elements
        for script in soup(["script", "style", "meta", "noscript", "header", "footer", "nav"]):
            script.extract()
        
        # Get text
        text = soup.get_text()
        
        # Break into lines and remove leading/trailing space
        lines = (line.strip() for line in text.splitlines())
        
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        
        # Drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    
    def crawl(self, start_url: str, depth=2, keywords=None) -> Dict[str, Any]:
        """
        Crawl a website to gather information.
        
        Args:
            start_url: Starting URL
            depth: Maximum crawl depth
            keywords: Optional list of keywords to look for
            
        Returns:
            Dictionary with crawl results
        """
        if depth <= 0 or len(self.visited_urls) >= self.max_pages:
            return {}
        
        if start_url in self.visited_urls:
            return {}
        
        self.visited_urls.add(start_url)
        
        html = self.fetch_url(start_url)
        if not html:
            return {}
        
        text = self.extract_text(html)
        
        # Check for keywords if provided
        keyword_matches = {}
        if keywords:
            for keyword in keywords:
                pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
                matches = pattern.findall(text)
                if matches:
                    keyword_matches[keyword] = len(matches)
        
        # Extract links for further crawling
        soup = BeautifulSoup(html, "html.parser")
        links = []
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            
            # Skip certain links
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            
            # Handle relative URLs
            if not bool(urlparse(href).netloc):
                href = urljoin(start_url, href)
            
            # Stay on the same domain
            if urlparse(href).netloc == urlparse(start_url).netloc:
                links.append(href)
        
        # Create the result for this page
        result = {
            "url": start_url,
            "title": soup.title.string if soup.title else "",
            "text": text[:1000] + "..." if len(text) > 1000 else text,  # Truncate long text
            "keyword_matches": keyword_matches,
            "subpages": {}
        }
        
        # Recursively crawl linked pages
        for link in links[:5]:  # Limit to 5 links per page
            if link not in self.visited_urls and len(self.visited_urls) < self.max_pages:
                subpage_result = self.crawl(link, depth - 1, keywords)
                if subpage_result:
                    result["subpages"][link] = subpage_result
        
        return result
    
    def analyze_cryptographic_information(self, query: str) -> Dict[str, Any]:
        """
        Search and analyze information related to a cryptographic puzzle.
        
        Args:
            query: Search query related to the puzzle
            
        Returns:
            Analysis results
        """
        results = self.search(query)
        
        if not results:
            return {
                "success": False,
                "message": "No search results found",
                "data": {}
            }
        
        # Collect and analyze information from the search results
        collected_info = []
        cryptographic_techniques = set()
        
        for result in results[:3]:  # Analyze top 3 results
            url = result["url"]
            html = self.fetch_url(url)
            
            if not html:
                continue
                
            text = self.extract_text(html)
            
            # Look for cryptographic techniques
            crypto_patterns = [
                (r'\b(aes|rijndael)\b', "AES Encryption"),
                (r'\b(rsa)\b', "RSA Encryption"),
                (r'\b(des|3des|triple des)\b', "DES Encryption"),
                (r'\b(blowfish)\b', "Blowfish"),
                (r'\b(twofish)\b', "Twofish"),
                (r'\b(sha-?1|sha-?256|sha-?512|md5)\b', "Hash Functions"),
                (r'\b(base64|base32|base16)\b', "Base Encoding"),
                (r'\b(xor)\b', "XOR Cipher"),
                (r'\b(caesar|rot13)\b', "Caesar/ROT Cipher"),
                (r'\b(vigenere|vigenère)\b', "Vigenère Cipher"),
                (r'\b(substitution cipher)\b', "Substitution Cipher"),
                (r'\b(steganography)\b', "Steganography"),
                (r'\b(blockchain|bitcoin|ethereum)\b', "Blockchain"),
                (r'\b(pgp|gpg)\b', "PGP/GPG Encryption"),
                (r'\b(hmac)\b', "HMAC"),
                (r'\b(elliptic curve|ecc|ecdsa)\b', "Elliptic Curve Cryptography"),
                (r'\b(diffie-hellman)\b', "Diffie-Hellman"),
                (r'\b(one-time pad|otp)\b', "One-Time Pad"),
                (r'\b(enigma)\b', "Enigma"),
                (r'\b(morse code)\b', "Morse Code"),
                (r'\b(binary|hexadecimal|hex dump)\b', "Binary/Hex Encoding"),
                (r'\b(transposition|permutation)\b', "Transposition Cipher"),
                (r'\b(ascii)\b', "ASCII Encoding"),
                (r'\b(atbash)\b', "Atbash Cipher")
            ]
            
            for pattern, technique in crypto_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    cryptographic_techniques.add(technique)
            
            # Extract a summary
            summary = text[:500] + "..." if len(text) > 500 else text
            
            collected_info.append({
                "title": result["title"],
                "url": url,
                "summary": summary
            })
        
        return {
            "success": True,
            "message": f"Found {len(collected_info)} relevant pages",
            "data": {
                "search_query": query,
                "results": collected_info,
                "cryptographic_techniques": list(cryptographic_techniques)
            }
        }
    
    def integrate_with_state(self, state, query: str) -> Any:
        """
        Integrate web browsing results with the puzzle state.
        
        Args:
            state: Current puzzle state
            query: Search query
            
        Returns:
            Updated state
        """
        analysis = self.analyze_cryptographic_information(query)
        
        if not analysis["success"]:
            state.add_insight(f"Web search failed: {analysis['message']}", analyzer="web_agent")
            return state
        
        # Add insights from web search
        state.add_insight(
            f"Web search for '{query}' found {len(analysis['data']['results'])} relevant pages",
            analyzer="web_agent"
        )
        
        # Add detected techniques
        techniques = analysis["data"]["cryptographic_techniques"]
        if techniques:
            state.add_insight(
                f"Detected possible techniques: {', '.join(techniques)}",
                analyzer="web_agent"
            )
        
        # Add detailed information for each result
        for i, result in enumerate(analysis["data"]["results"], 1):
            state.add_transformation(
                name=f"Web Search Result {i}",
                description=f"Information from {result['title']}",
                input_data=query,
                output_data=result["summary"],
                analyzer="web_agent"
            )
        
        return state
