# core/private_key_constructor_agent.py
"""
PrivateKeyConstructorAgent
Looks for RSA parameters in findings and reconstructs private keys.
"""
import logging
import os
from Crypto.PublicKey import RSA
from enhanced_state_management import Material, MaterialType

logger = logging.getLogger(__name__)

class PrivateKeyConstructorAgent:
    def __init__(self, verbose: bool = False, output_dir: str = "keys"):
        self.verbose    = verbose
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def run(self, state):
        """
        Scan findings for 'modulus', 'public_exponent', 'private_exponent'.
        If all three present, build RSA key and save as PEM.
        """
        n = e = d = None
        for f in state.get_high_confidence_findings():
            # expecting f to have 'type' and 'data' fields
            if f.get("type") == "modulus":
                try: n = int(f.get("data"))
                except: pass
            if f.get("type") == "public_exponent":
                try: e = int(f.get("data"))
                except: pass
            if f.get("type") == "private_exponent":
                try: d = int(f.get("data"))
                except: pass

        if n and e and d:
            try:
                key = RSA.construct((n, e, d))
                pem = key.export_key().decode()
                fname = os.path.join(self.output_dir, f"rsa_{key.n:x}_private.pem")
                with open(fname, "w") as fd:
                    fd.write(pem)
                # register as material
                mat = Material(
                    id=f"privkey-{os.path.basename(fname)}",
                    file_path=fname,
                    material_type=MaterialType.FILE
                )
                state.add_material(mat)
                state.add_finding({
                    "source": "private_key_constructor_agent",
                    "type":   "private_key",
                    "pem":    pem
                })
                if self.verbose:
                    logger.info(f"[PKConstructor] wrote {fname}")
            except Exception as ex:
                logger.warning(f"PrivateKeyConstructor failed: {ex}")
        else:
            if self.verbose:
                logger.debug("[PKConstructor] no complete RSA params found")
        return state
