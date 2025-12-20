# session_manager.py - FIXAD VERSION

from datetime import datetime
from typing import Dict, Optional

class ActiveSessionManager:
    """
    Håller koll på aktiva sessioner.
    Endast EN aktiv session per användare tillåts.
    """
    
    def __init__(self):
        # user_id -> {"jti": str, "created_at": str}
        self._active_sessions: Dict[int, Dict] = {}
        print("🔐 ActiveSessionManager initierad")
    
    def create_session(self, user_id: int, jti: str) -> str:
        """
        Skapa en ny session för användaren.
        Invaliderar automatiskt eventuell tidigare session.
        Returnerar session JTI (JWT ID).
        """
        # Kolla om användaren redan har en aktiv session
        if user_id in self._active_sessions:
            old_jti = self._active_sessions[user_id]["jti"]
            print(f"⚠️  Användare {user_id} hade redan en session ({old_jti[:8]}...) - invaliderar den")
        
        # Skapa ny session (ersätter gamla)
        self._active_sessions[user_id] = {
            "jti": jti,
            "created_at": datetime.utcnow().isoformat()
        }
        
        print(f"✅ Ny session skapad för användare {user_id}: {jti[:8]}...")
        return jti
    
    def is_valid_session(self, user_id: int, jti: str) -> bool:
        """
        Kontrollera om en session är giltig.
        En session är giltig om:
        1. Användaren har en aktiv session
        2. JTI matchar den aktiva sessionen
        """
        if user_id not in self._active_sessions:
            print(f"⛔ Ingen aktiv session för användare {user_id}")
            return False
        
        active_jti = self._active_sessions[user_id]["jti"]
        is_valid = active_jti == jti
        
        if not is_valid:
            print(f"⛔ Ogiltig session för användare {user_id}: {jti[:8]}... (aktiv: {active_jti[:8]}...)")
        
        return is_valid
    
    def invalidate_session(self, user_id: int):
        """
        Invalidera sessionen för en användare.
        Kallas vid explicit logout/clear_all.
        """
        if user_id in self._active_sessions:
            jti = self._active_sessions[user_id]["jti"]
            del self._active_sessions[user_id]
            print(f"🔒 Session invaliderad för användare {user_id}: {jti[:8]}...")
        else:
            print(f"⚠️  Ingen aktiv session att invalidera för användare {user_id}")
    
    def get_active_jti(self, user_id: int) -> Optional[str]:
        """Hämta den aktiva JTI för en användare"""
        if user_id in self._active_sessions:
            return self._active_sessions[user_id]["jti"]
        return None
    
    def get_all_sessions(self) -> Dict[int, Dict]:
        """Hämta alla aktiva sessioner (för debugging)"""
        return self._active_sessions.copy()
    
    def cleanup_expired_sessions(self):
        """
        Rensa utgångna sessioner.
        (I detta system hanteras expiry av JWT tokens själva)
        """
        pass
    
    def clear_all_sessions(self):
        """Rensa ALLA sessioner (vid server restart)"""
        count = len(self._active_sessions)
        self._active_sessions.clear()
        print(f"🧹 Rensade {count} sessioner vid restart")

# Singleton instance
active_session_manager = ActiveSessionManager()