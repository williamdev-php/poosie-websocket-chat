import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from config import config

class AdvancedEncryption:
    """
    Förbättrad kryptering med unika salts per meddelande.
    Stödjer både meddelanden och JSON-data.
    """
    
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
        print("🔐 AdvancedEncryption initierad")
    
    def _get_or_create_master_key(self) -> bytes:
        """Hämta eller skapa master key från config"""
        key = config.ENCRYPTION_KEY
        
        if key == "your-secret-key-here-generate-new-one":
            if config.IS_PRODUCTION:
                raise ValueError("ENCRYPTION_KEY måste sättas i produktion!")
            # Generera temporär nyckel för utveckling
            print("⚠️  VARNING: Använder genererad nyckel. Sätt ENCRYPTION_KEY för produktion!")
            return Fernet.generate_key()
        
        # Validera om det är en giltig Fernet-nyckel
        try:
            return key.encode() if isinstance(key, str) else key
        except Exception:
            # Derivera från lösenord
            return self._derive_key_from_password(key)
    
    def _derive_key_from_password(self, password: str) -> bytes:
        """Derivera Fernet-nyckel från lösenord"""
        # Använd ett unikt salt per installation (från env eller genererat)
        salt_env = os.getenv("ENCRYPTION_SALT")
        if salt_env:
            salt = base64.urlsafe_b64decode(salt_env)
        else:
            salt = b'websocket_chat_unique_salt_v2'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommendation 2023
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_message(self, message: str) -> dict:
        """
        Kryptera ett meddelande med unikt salt.
        Returnerar: {"encrypted": str, "salt": str}
        """
        if not message:
            return {"encrypted": "", "salt": ""}
        
        # Generera unikt salt för detta meddelande
        salt = os.urandom(16)
        
        # Derivera unik nyckel från master key + salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        
        # Kryptera med den härledda nyckeln
        fernet = Fernet(derived_key)
        encrypted = fernet.encrypt(message.encode('utf-8'))
        
        return {
            "encrypted": base64.urlsafe_b64encode(encrypted).decode('utf-8'),
            "salt": base64.urlsafe_b64encode(salt).decode('utf-8')
        }
    
    def decrypt_message(self, encrypted_data: dict) -> str:
        """
        Dekryptera ett meddelande med dess salt.
        Input: {"encrypted": str, "salt": str}
        """
        if not encrypted_data or not encrypted_data.get("encrypted"):
            return ""
        
        try:
            encrypted = encrypted_data["encrypted"]
            salt = base64.urlsafe_b64decode(encrypted_data["salt"])
            
            # Återskapa samma härledda nyckel
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
            
            # Dekryptera
            fernet = Fernet(derived_key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted.encode('utf-8'))
            decrypted = fernet.decrypt(encrypted_bytes)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"❌ Dekrypteringsfel: {e}")
            return "[Kunde inte dekryptera meddelande]"
    
    def encrypt_json(self, data: dict) -> str:
        """Kryptera JSON-data (för filer)"""
        if not data:
            return ""
        
        json_str = json.dumps(data, ensure_ascii=False)
        result = self.encrypt_message(json_str)
        
        # Returnera kombinerad sträng: salt:encrypted
        return f"{result['salt']}:{result['encrypted']}"
    
    def decrypt_json(self, encrypted_str: str) -> dict:
        """Dekryptera JSON-data"""
        if not encrypted_str:
            return {}
        
        try:
            salt, encrypted = encrypted_str.split(":", 1)
            decrypted = self.decrypt_message({"salt": salt, "encrypted": encrypted})
            return json.loads(decrypted)
        except Exception as e:
            print(f"❌ JSON dekrypteringsfel: {e}")
            return {}
    
    def encrypt_field(self, value: str) -> dict:
        """Kryptera ett enskilt fält (t.ex. IP-adress)"""
        return self.encrypt_message(value)
    
    def decrypt_field(self, encrypted_data: dict) -> str:
        """Dekryptera ett enskilt fält"""
        return self.decrypt_message(encrypted_data)

# Singleton
encryption = AdvancedEncryption()

# Convenience functions
def encrypt_message(message: str) -> dict:
    return encryption.encrypt_message(message)

def decrypt_message(encrypted_data: dict) -> str:
    return encryption.decrypt_message(encrypted_data)

def encrypt_json(data: dict) -> str:
    return encryption.encrypt_json(data)

def decrypt_json(encrypted_str: str) -> dict:
    return encryption.decrypt_json(encrypted_str)

# Generera ny nyckel för produktion
def generate_new_key() -> str:
    """Generera en ny Fernet-nyckel"""
    return Fernet.generate_key().decode()

def generate_salt() -> str:
    """Generera ett nytt salt"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()

if __name__ == "__main__":
    print("🔑 Generera nya nycklar för produktion:")
    print(f"\nENCRYPTION_KEY={generate_new_key()}")
    print(f"ENCRYPTION_SALT={generate_salt()}")
    print(f"JWT_SECRET={generate_new_key()}")
    print(f"SESSION_API_TOKEN={generate_new_key()}")