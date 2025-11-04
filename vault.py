import gnupg
import yaml
from pathlib import Path

class GPGVault:

    def __init__(self, path='./.secrets', gpg_homedir=None):
        self.gpg = gnupg.GPG(gnupghome=gpg_homedir)
        self.path = Path(path)

        if not self.path.is_file():
            raise FileNotFoundError(f"{path} not found")
                
        with open(path, "rb") as f:
            status = self.gpg.decrypt_file(f, output=None)
        if not status.ok:
            raise RuntimeError(f"GPG decryption failed: {status.stderr}")
        
        self.data = yaml.safe_load(status.data)
        if not isinstance(self.data, dict):
            raise ValueError("YAML content must be a dictionary at top level")

    def get(self, key_path, default=None):
        keys = key_path.split(".")
        current = self.data
        for k in keys:
            if not isinstance(current, dict) or k not in current:
                return default
            current = current[k]
        return current