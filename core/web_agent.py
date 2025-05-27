# core/web_agent.py
"""
WebAgent: uses DuckDuckGo search + scraping to enrich state insights.
Works with either ddg() or search() from duckduckgo_search.
"""
import logging
import requests
from bs4 import BeautifulSoup

# try both APIs
try:
    from duckduckgo_search import ddg
except ImportError:
    try:
        from duckduckgo_search import search as ddg
    except ImportError:
        ddg = None

class WebAgent:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger  = logging.getLogger(__name__)

    def run(self, state):
        if not ddg:
            if self.verbose:
                self.logger.warning("duckduckgo_search API not available, skipping WebAgent")
            return state

        insights = [f.get("text","") for f in state.get_high_confidence_findings()]
        for query in insights:
            if not query:
                continue
            try:
                results = ddg(query, max_results=1)
                if not results:
                    continue

                # ddg() old API returns list of dicts; new search() returns list of URLs
                if isinstance(results[0], dict):
                    link  = results[0].get("href") or results[0].get("url")
                    title = results[0].get("title","")
                else:
                    link  = results[0]
                    title = link

                snippet = self._scrape_snippet(link)
                finding = {
                    "source":  "web_agent",
                    "type":    "web_snippet",
                    "query":   query,
                    "title":   title,
                    "url":     link,
                    "snippet": snippet
                }
                state.add_finding(finding)
                if self.verbose:
                    self.logger.info(f"WebAgent: {query!r} → {link}")
            except Exception as e:
                self.logger.warning(f"WebAgent error on {query!r}: {e}")
        return state

    def _scrape_snippet(self, url: str, length: int = 200) -> str:
        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            text = " ".join(soup.stripped_strings)
            return text[:length]
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Failed scraping {url}: {e}")
            return ""
