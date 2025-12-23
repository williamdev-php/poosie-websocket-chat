import os
import json
from datetime import datetime
from typing import Dict, Optional
from pydantic import BaseModel

LOGIN_CONTROL_FILE = "data/login_control.json"

class LoginAttempt(BaseModel):
    """Loggad inloggningsförsök"""
    timestamp: str
    user_id: int
    ip_address: str
    user_agent: str
    success: bool
    reason: Optional[str] = None

class LoginControl:
    """
    Kontrollerar vem som får logga in.
    User_id 2 kan alltid logga in.
    User_id 1's inloggning kan stängas av av user_id 2.
    """
    
    def __init__(self):
        self._ensure_data_dir()
        self._state = self._load_state()
        self._attempts: list = []
        print(f"🔐 LoginControl initierad - User 1 login: {'🟢 PÅ' if self._state.get('user_1_enabled', True) else '🔴 AV'}")
    
    def _ensure_data_dir(self):
        """Skapa data-katalog om den inte finns"""
        os.makedirs("data", exist_ok=True)
    
    def _load_state(self) -> Dict:
        """Ladda login control state"""
        if os.path.exists(LOGIN_CONTROL_FILE):
            try:
                with open(LOGIN_CONTROL_FILE, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            except Exception as e:
                print(f"⚠️ Kunde inte ladda login control: {e}")
        
        # Default: båda användare kan logga in
        default = {
            "user_1_enabled": True,
            "user_2_enabled": True,  # Alltid true (kan inte stängas av)
            "last_modified": datetime.utcnow().isoformat(),
            "modified_by": None
        }
        self._save_state(default)
        return default
    
    def _save_state(self, state: Dict):
        """Spara login control state"""
        try:
            with open(LOGIN_CONTROL_FILE, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Kunde inte spara login control: {e}")
    
    def is_login_allowed(self, user_id: int) -> tuple[bool, Optional[str]]:
        """
        Kontrollera om en användare får logga in.
        Returnerar (allowed, reason)
        """
        # User 2 kan alltid logga in
        if user_id == 2:
            return True, None
        
        # User 1 beror på state
        if user_id == 1:
            if self._state.get("user_1_enabled", True):
                return True, None
            else:
                return False, "Login temporarily disabled"
        
        # Okänd användare
        return False, "Invalid user"
    
    def toggle_user_1_login(self, enabled: bool, modified_by: int) -> Dict:
        """
        Sätt på/av login för user_id 1.
        Endast user_id 2 kan göra detta.
        """
        if modified_by != 2:
            return {
                "error": "Only user_id 2 can control login access",
                "success": False
            }
        
        old_state = self._state.get("user_1_enabled", True)
        self._state["user_1_enabled"] = enabled
        self._state["last_modified"] = datetime.utcnow().isoformat()
        self._state["modified_by"] = modified_by
        
        self._save_state(self._state)
        
        status = "🟢 PÅ" if enabled else "🔴 AV"
        print(f"🔐 User 1 login: {status} (ändrad av user {modified_by})")
        
        return {
            "success": True,
            "user_1_enabled": enabled,
            "changed_from": old_state,
            "changed_to": enabled,
            "modified_by": modified_by,
            "timestamp": self._state["last_modified"]
        }
    
    def get_status(self) -> Dict:
        """Hämta current login status"""
        return {
            "user_1_enabled": self._state.get("user_1_enabled", True),
            "user_2_enabled": True,  # Alltid true
            "last_modified": self._state.get("last_modified"),
            "modified_by": self._state.get("modified_by")
        }
    
    def log_attempt(self, user_id: int, ip_address: str, user_agent: str, 
                   success: bool, reason: Optional[str] = None):
        """Logga ett inloggningsförsök"""
        attempt = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "reason": reason
        }
        
        self._attempts.append(attempt)
        
        # Behåll endast senaste 100 försök
        if len(self._attempts) > 100:
            self._attempts = self._attempts[-100:]
        
        # Logga till konsolen
        status = "✅ GODKÄND" if success else "❌ NEKAD"
        print(f"🔐 Login försök: User {user_id} från {ip_address} - {status}")
        if reason:
            print(f"   Anledning: {reason}")
    
    def get_recent_attempts(self, limit: int = 20) -> list:
        """Hämta senaste inloggningsförsöken"""
        return self._attempts[-limit:]

# Singleton
login_control = LoginControl()