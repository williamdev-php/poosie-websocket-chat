# session_tracker.py - Hanterar sessionsloggning och säkerhetskontroll

import os
import json
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# Filvägar för lagring
SESSIONS_FILE = "data/sessions.json"
TRUSTED_FILE = "data/trusted_devices.json"
ONBOARDING_FILE = "data/onboarding.json"

# API token från .env
API_TOKEN = os.getenv("SESSION_API_TOKEN", "super-secret-token-change-me")

class DeviceStatus(str, Enum):
    UNKNOWN = "unknown"      # Ej markerad - Avvikelse
    TRUSTED = "trusted"      # Säker
    BLOCKED = "blocked"      # Osäker/blockerad

class SessionLog(BaseModel):
    id: str
    user_id: int
    ip_address: str
    user_agent: str
    browser: str
    os: str
    device_type: str  # mobile/desktop/tablet
    timestamp: str
    fingerprint: str  # Hash av IP + User-Agent för identifiering

class TrustedDevice(BaseModel):
    fingerprint: str
    ip_address: str
    user_agent: str
    status: DeviceStatus
    marked_by: int  # user_id som markerade
    marked_at: str
    note: Optional[str] = None

class OnboardingStatus(BaseModel):
    user_id: int
    completed: bool
    login_count: int
    dont_show_again: bool

def ensure_data_dir():
    """Skapa data-mappen om den inte finns"""
    os.makedirs("data", exist_ok=True)

def load_json_file(filepath: str, default: any = None) -> any:
    """Ladda JSON-fil, returnera default om den inte finns"""
    ensure_data_dir()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:  # Tom fil
                    return default if default is not None else {}
                return json.loads(content)
        except json.JSONDecodeError:
            # Fil finns men är korrupt/tom - returnera default
            return default if default is not None else {}
        except Exception as e:
            print(f"⚠️ Kunde inte läsa {filepath}: {e}")
    return default if default is not None else {}

def save_json_file(filepath: str, data: any):
    """Spara data till JSON-fil"""
    ensure_data_dir()
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"❌ Kunde inte spara {filepath}: {e}")

def generate_fingerprint(ip: str, user_agent: str) -> str:
    """Generera ett fingerprint från IP och User-Agent"""
    import hashlib
    data = f"{ip}:{user_agent}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]

def parse_user_agent(user_agent: str) -> dict:
    """Enkel parsing av User-Agent för browser, OS och device"""
    ua_lower = user_agent.lower()
    
    # Browser
    browser = "Okänd"
    if "edg/" in ua_lower or "edge" in ua_lower:
        browser = "Edge"
    elif "chrome" in ua_lower and "safari" in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "opera" in ua_lower or "opr/" in ua_lower:
        browser = "Opera"
    
    # OS
    os_name = "Okänt"
    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macos" in ua_lower:
        os_name = "macOS"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "linux" in ua_lower:
        os_name = "Linux"
    
    # Device type
    device_type = "desktop"
    if "mobile" in ua_lower or "iphone" in ua_lower or "android" in ua_lower:
        if "tablet" in ua_lower or "ipad" in ua_lower:
            device_type = "tablet"
        else:
            device_type = "mobile"
    
    return {
        "browser": browser,
        "os": os_name,
        "device_type": device_type
    }

class SessionTracker:
    """Hanterar sessionsloggning och säkerhetskontroll"""
    
    def __init__(self):
        self._sessions: List[dict] = load_json_file(SESSIONS_FILE, [])
        self._trusted: Dict[str, dict] = load_json_file(TRUSTED_FILE, {})
        self._onboarding: Dict[str, dict] = load_json_file(ONBOARDING_FILE, {})
        print(f"📊 SessionTracker laddad: {len(self._sessions)} sessioner, {len(self._trusted)} enheter")
    
    def verify_token(self, token: str) -> bool:
        """Verifiera API token"""
        return token == API_TOKEN
    
    def log_session(self, user_id: int, ip_address: str, user_agent: str) -> dict:
        """Logga en ny session för user_id 1"""
        if user_id != 1:
            return {"status": "ignored", "reason": "Only user_id 1 is tracked"}
        
        parsed = parse_user_agent(user_agent)
        fingerprint = generate_fingerprint(ip_address, user_agent)
        
        session = {
            "id": f"sess_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{fingerprint[:8]}",
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "browser": parsed["browser"],
            "os": parsed["os"],
            "device_type": parsed["device_type"],
            "timestamp": datetime.utcnow().isoformat(),
            "fingerprint": fingerprint
        }
        
        self._sessions.append(session)
        
        # Behåll bara senaste 100 sessioner
        if len(self._sessions) > 100:
            self._sessions = self._sessions[-100:]
        
        save_json_file(SESSIONS_FILE, self._sessions)
        print(f"📝 Session loggad: {session['id']} från {ip_address}")
        
        return session
    
    def check_device_status(self, ip_address: str, user_agent: str) -> dict:
        """Kontrollera om en enhet är trusted/blocked/unknown"""
        fingerprint = generate_fingerprint(ip_address, user_agent)
        
        if fingerprint in self._trusted:
            device = self._trusted[fingerprint]
            return {
                "allowed": device["status"] != DeviceStatus.BLOCKED.value,
                "status": device["status"],
                "fingerprint": fingerprint,
                "is_anomaly": device["status"] == DeviceStatus.UNKNOWN.value
            }
        
        # Okänd enhet - tillåt men markera som avvikelse
        return {
            "allowed": True,
            "status": DeviceStatus.UNKNOWN.value,
            "fingerprint": fingerprint,
            "is_anomaly": True
        }
    
    def mark_device(self, fingerprint: str, status: DeviceStatus, marked_by: int, note: str = None) -> dict:
        """Markera en enhet som trusted/blocked"""
        if marked_by != 2:
            return {"error": "Only user_id 2 can mark devices"}
        
        # Hitta session med detta fingerprint för att få IP och UA
        session = next((s for s in self._sessions if s.get("fingerprint") == fingerprint), None)
        
        if not session and fingerprint not in self._trusted:
            return {"error": "Fingerprint not found"}
        
        ip = session["ip_address"] if session else self._trusted.get(fingerprint, {}).get("ip_address", "unknown")
        ua = session["user_agent"] if session else self._trusted.get(fingerprint, {}).get("user_agent", "unknown")
        
        self._trusted[fingerprint] = {
            "fingerprint": fingerprint,
            "ip_address": ip,
            "user_agent": ua,
            "status": status.value,
            "marked_by": marked_by,
            "marked_at": datetime.utcnow().isoformat(),
            "note": note
        }
        
        save_json_file(TRUSTED_FILE, self._trusted)
        print(f"✅ Enhet {fingerprint} markerad som {status.value}")
        
        return self._trusted[fingerprint]
    
    def get_all_sessions(self) -> List[dict]:
        """Hämta alla loggade sessioner"""
        # Lägg till status för varje session
        result = []
        for session in self._sessions:
            fp = session.get("fingerprint", "")
            device_info = self._trusted.get(fp, {})
            session_with_status = {
                **session,
                "device_status": device_info.get("status", DeviceStatus.UNKNOWN.value),
                "is_anomaly": device_info.get("status", DeviceStatus.UNKNOWN.value) == DeviceStatus.UNKNOWN.value
            }
            result.append(session_with_status)
        return result
    
    def get_trusted_devices(self) -> Dict[str, dict]:
        """Hämta alla markerade enheter"""
        return self._trusted
    
    def get_anomalies(self) -> List[dict]:
        """Hämta sessioner som är avvikelser (okända enheter)"""
        return [s for s in self.get_all_sessions() if s.get("is_anomaly", True)]
    
    # Onboarding funktioner
    def get_onboarding_status(self, user_id: int) -> dict:
        """Hämta onboarding-status för en användare"""
        key = str(user_id)
        if key not in self._onboarding:
            self._onboarding[key] = {
                "user_id": user_id,
                "completed": False,
                "login_count": 0,
                "dont_show_again": False
            }
            save_json_file(ONBOARDING_FILE, self._onboarding)
        return self._onboarding[key]
    
    def increment_login_count(self, user_id: int) -> dict:
        """Öka inloggningsräknaren"""
        status = self.get_onboarding_status(user_id)
        status["login_count"] += 1
        
        # Auto-complete efter 2 inloggningar om inte dismiss
        if status["login_count"] >= 2 and not status["dont_show_again"]:
            status["completed"] = True
        
        self._onboarding[str(user_id)] = status
        save_json_file(ONBOARDING_FILE, self._onboarding)
        return status
    
    def dismiss_onboarding(self, user_id: int) -> dict:
        """Användaren vill inte se onboarding mer"""
        status = self.get_onboarding_status(user_id)
        status["dont_show_again"] = True
        status["completed"] = True
        self._onboarding[str(user_id)] = status
        save_json_file(ONBOARDING_FILE, self._onboarding)
        return status
    
    def should_show_onboarding(self, user_id: int) -> bool:
        """Kontrollera om onboarding ska visas"""
        if user_id != 1:
            return False
        status = self.get_onboarding_status(user_id)
        return not status["completed"] and not status["dont_show_again"]

# Singleton instans
tracker = SessionTracker()