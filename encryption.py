import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()

class MessageEncryption:
    def __init__(self):
        key = os.getenv("ENCRYPTION_KEY")
        if not key or key == "your-secret-key-here-generate-new-one":
            # Generera en tillfällig nyckel för utveckling
            print("⚠️  VARNING: Använder genererad nyckel. Sätt ENCRYPTION_KEY i .env för produktion!")
            key = Fernet.generate_key().decode()
        
        # Om nyckeln inte är en giltig Fernet-nyckel, skapa en från den
        try:
            self.fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception:
            # Derivera en nyckel från den givna strängen
            self.fernet = Fernet(self._derive_key(key))
    
    def _derive_key(self, password: str) -> bytes:
        """Derivera en Fernet-kompatibel nyckel från ett lösenord"""
        salt = b'websocket_chat_salt_v1'  # Fast salt för konsistens
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, message: str) -> str:
        """Kryptera ett meddelande"""
        if not message:
            return ""
        encrypted = self.fernet.encrypt(message.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_message: str) -> str:
        """Dekryptera ett meddelande"""
        if not encrypted_message:
            return ""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Dekrypteringsfel: {e}")
            return "[Kunde inte dekryptera meddelande]"

# Singleton instans
encryption = MessageEncryption()

def encrypt_message(message: str) -> str:
    return encryption.encrypt(message)

def decrypt_message(encrypted: str) -> str:
    return encryption.decrypt(encrypted)

# Generera ny nyckel för produktion
def generate_new_key() -> str:
    """Generera en ny Fernet-nyckel"""
    return Fernet.generate_key().decode()

if __name__ == "__main__":
    print("Ny krypteringsnyckel:")
    print(generate_new_key())