# core/wallet_verifier_agent.py
"""
WalletVerifierAgent — offline address derivation for ETH & BTC.
Extracts addresses from private keys/WIFs without network calls.
"""
import re
import logging
from enhanced_state_management import MaterialType

# eth_account derives ETH addresses offline
from eth_account import Account
# bit derives BTC addresses offline
try:
    from bit import Key
except ImportError:
    Key = None
    logging.getLogger(__name__).warning(
        "bit library not found—skipping BTC address derivation"
    )

logger = logging.getLogger(__name__)

class WalletVerifierAgent:
    def __init__(self, verbose: bool = False):
        """
        verbose: whether to log detailed info
        """
        self.verbose = verbose

    def run(self, state):
        """
        Scan findings for ETH private keys (0xhex64) and BTC WIFs,
        derive addresses offline, and record as new findings.
        """
        pattern_eth = re.compile(r"0x[a-fA-F0-9]{64}")
        pattern_btc = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")

        # collect all text fields
        texts = []
        for f in state.get_all_findings():
            for field in ("text", "pem", "private_key", "wif"):
                if field in f and isinstance(f[field], str):
                    texts.append(f[field])

        seen = set()
        for txt in texts:
            # ETH
            for m in pattern_eth.findall(txt):
                if m in seen:
                    continue
                seen.add(m)
                try:
                    acct = Account.from_key(m)
                    addr = acct.address
                    state.add_finding({
                        "source":      "wallet_verifier_agent",
                        "type":        "eth_wallet",
                        "private_key": m,
                        "address":     addr
                    })
                    if self.verbose:
                        logger.info(f"[ETH] derived {addr} from {m[:6]}…")
                except Exception as e:
                    logger.warning(f"[ETH] failed to derive address: {e}")

            # BTC
            if Key:
                for m in pattern_btc.findall(txt):
                    if m in seen:
                        continue
                    seen.add(m)
                    try:
                        key = Key(m)
                        addr = key.address
                        state.add_finding({
                            "source":  "wallet_verifier_agent",
                            "type":    "btc_wallet",
                            "wif":     m,
                            "address": addr
                        })
                        if self.verbose:
                            logger.info(f"[BTC] derived {addr} from WIF")
                    except Exception as e:
                        logger.warning(f"[BTC] failed to derive address: {e}")

        return state
