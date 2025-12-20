import sqlite3
import os
from datetime import datetime, timedelta
from typing import Optional, Dict
from config import config
from encryption import encryption

class LastSeenStore:
    """
    SQLite-baserad lagring för last seen data.
    All data krypteras innan lagring.
    """
    
    def __init__(self):
        self.db_path = config.DB_PATH
        self._ensure_db_dir()
        self._init_db()
        print(f"📊 LastSeenStore initierad: {self.db_path}")
    
    def _ensure_db_dir(self):
        """Skapa data-katalog om den inte finns"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    
    def _init_db(self):
        """Initiera databastabeller"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS last_seen (
                    user_id INTEGER PRIMARY KEY,
                    last_seen_at TEXT NOT NULL,
                    last_ip_encrypted TEXT,
                    last_ip_salt TEXT,
                    user_agent_encrypted TEXT,
                    user_agent_salt TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.commit()
    
    def update_last_seen(self, user_id: int, ip_address: str = None, user_agent: str = None):
        """Uppdatera last seen för en användare"""
        now = datetime.utcnow().isoformat()
        
        # Kryptera IP och user agent
        ip_data = encryption.encrypt_field(ip_address) if ip_address else {"encrypted": "", "salt": ""}
        ua_data = encryption.encrypt_field(user_agent) if user_agent else {"encrypted": "", "salt": ""}
        
        with sqlite3.connect(self.db_path) as conn:
            # Kolla om användaren redan finns
            existing = conn.execute(
                "SELECT user_id FROM last_seen WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            
            if existing:
                # Uppdatera
                conn.execute("""
                    UPDATE last_seen 
                    SET last_seen_at = ?,
                        last_ip_encrypted = ?,
                        last_ip_salt = ?,
                        user_agent_encrypted = ?,
                        user_agent_salt = ?,
                        updated_at = ?
                    WHERE user_id = ?
                """, (
                    now,
                    ip_data["encrypted"],
                    ip_data["salt"],
                    ua_data["encrypted"],
                    ua_data["salt"],
                    now,
                    user_id
                ))
            else:
                # Skapa ny
                conn.execute("""
                    INSERT INTO last_seen (
                        user_id, last_seen_at,
                        last_ip_encrypted, last_ip_salt,
                        user_agent_encrypted, user_agent_salt,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, now,
                    ip_data["encrypted"], ip_data["salt"],
                    ua_data["encrypted"], ua_data["salt"],
                    now, now
                ))
            
            conn.commit()
    
    def get_last_seen(self, user_id: int, decrypt: bool = False) -> Optional[Dict]:
        """
        Hämta last seen för en användare.
        Om decrypt=True, dekryptera IP och user agent.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM last_seen WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            
            if not row:
                return None
            
            result = {
                "user_id": row["user_id"],
                "last_seen_at": row["last_seen_at"],
                "last_seen_ago": self._format_time_ago(row["last_seen_at"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"]
            }
            
            if decrypt and row["last_ip_encrypted"]:
                result["last_ip"] = encryption.decrypt_field({
                    "encrypted": row["last_ip_encrypted"],
                    "salt": row["last_ip_salt"]
                })
                result["user_agent"] = encryption.decrypt_field({
                    "encrypted": row["user_agent_encrypted"],
                    "salt": row["user_agent_salt"]
                })
            
            return result
    
    def get_all_last_seen(self, decrypt: bool = False) -> Dict[int, Dict]:
        """Hämta last seen för alla användare"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM last_seen").fetchall()
            
            result = {}
            for row in rows:
                user_id = row["user_id"]
                result[user_id] = {
                    "user_id": user_id,
                    "last_seen_at": row["last_seen_at"],
                    "last_seen_ago": self._format_time_ago(row["last_seen_at"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                }
                
                if decrypt and row["last_ip_encrypted"]:
                    result[user_id]["last_ip"] = encryption.decrypt_field({
                        "encrypted": row["last_ip_encrypted"],
                        "salt": row["last_ip_salt"]
                    })
                    result[user_id]["user_agent"] = encryption.decrypt_field({
                        "encrypted": row["user_agent_encrypted"],
                        "salt": row["user_agent_salt"]
                    })
            
            return result
    
    def clear_old_data(self, days_old: int = 30):
        """Rensa data äldre än X dagar"""
        cutoff = (datetime.utcnow() - timedelta(days=days_old)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                "DELETE FROM last_seen WHERE updated_at < ?",
                (cutoff,)
            )
            conn.commit()
            deleted = result.rowcount
            
            if deleted > 0:
                print(f"🗑️  Rensade {deleted} gamla last_seen poster")
            
            return deleted
    
    def _format_time_ago(self, iso_timestamp: str) -> str:
        """Formatera tid sedan sist sedd (t.ex. '2 timmar sedan')"""
        try:
            last_seen = datetime.fromisoformat(iso_timestamp)
            now = datetime.utcnow()
            delta = now - last_seen
            
            seconds = delta.total_seconds()
            
            if seconds < 60:
                return "Just nu"
            elif seconds < 3600:
                minutes = int(seconds / 60)
                return f"{minutes} minut{'er' if minutes != 1 else ''} sedan"
            elif seconds < 86400:
                hours = int(seconds / 3600)
                return f"{hours} timm{'ar' if hours != 1 else 'e'} sedan"
            elif seconds < 2592000:  # 30 days
                days = int(seconds / 86400)
                return f"{days} dag{'ar' if days != 1 else ''} sedan"
            else:
                months = int(seconds / 2592000)
                return f"{months} månad{'er' if months != 1 else ''} sedan"
        except Exception as e:
            print(f"❌ Fel vid formatering av tid: {e}")
            return "Okänd tid"
    
    def vacuum(self):
        """Optimera databasen"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("VACUUM")
            print("🧹 Databas optimerad (VACUUM)")

# Singleton
last_seen_store = LastSeenStore()