# core/pgp_agent.py
"""
PGPAgent — decrypts PGP-encrypted materials using the system keyring.
Looks for files ending in .gpg/.pgp or containing “BEGIN PGP MESSAGE”,
runs `gpg --decrypt`, and registers the plaintext as a new material.
"""
import os
import subprocess
import logging

from enhanced_state_management import Material, MaterialType

logger = logging.getLogger(__name__)

class PGPAgent:
    def __init__(self, verbose: bool = False):
        """
        verbose: whether to emit debug logs
        """
        self.verbose = verbose
        self.logger  = logging.getLogger(__name__)

    def run(self, state):
        """
        Scan each binary material for PGP data, attempt decryption,
        add decrypted text as a new TEXT material and a finding.
        """
        for mat in list(state.materials.values()):
            if mat.material_type.lower() != MaterialType.BINARY:
                continue

            path = mat.file_path
            name = os.path.basename(path).lower()
            # Only target .gpg/.pgp or ASCII-armored
            want = name.endswith((".gpg", ".pgp"))
            if not want:
                try:
                    head = open(path, encoding="utf8", errors="ignore").read(64)
                    want = "BEGIN PGP MESSAGE" in head
                except:
                    want = False
            if not want:
                continue

            if self.verbose:
                self.logger.info(f"[PGPAgent] decrypting {mat.id} → {path}")

            try:
                proc = subprocess.run(
                    ["gpg", "--batch", "--yes", "--decrypt", path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if proc.returncode == 0:
                    plaintext = proc.stdout
                    out_name  = f"{os.path.splitext(path)[0]}_decrypted.txt"
                    with open(out_name, "w", encoding="utf8") as fd:
                        fd.write(plaintext)

                    new_mat = Material(
                        id=f"{mat.id}-pgp",
                        file_path=out_name,
                        material_type=MaterialType.TEXT
                    )
                    state.add_material(new_mat)
                    state.add_finding({
                        "source":      "pgp_agent",
                        "type":        "pgp_decrypt",
                        "material_id": new_mat.id,
                        "file":        out_name
                    })
                    if self.verbose:
                        self.logger.info(f"[PGPAgent] wrote decrypted text to {out_name}")
                else:
                    if self.verbose:
                        self.logger.warning(
                            f"[PGPAgent] gpg failed on {path}: {proc.stderr.strip()}"
                        )
            except Exception as e:
                self.logger.warning(f"[PGPAgent] error on {path}: {e}")

        return state
