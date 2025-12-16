import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from collections import OrderedDict
import uuid
from dotenv import load_dotenv
from models import Message, MessageStatus, MessageType, UserSession, UserStatus, USERS
from encryption import encrypt_message, decrypt_message

load_dotenv()

class MessageStore:
    """
    RAM-baserad meddelandelagring med automatisk radering.
    Använder OrderedDict för effektiv minneshantering.
    """
    
    def __init__(self):
        # Konfiguration från .env
        self.base_delete_time = int(os.getenv("BASE_DELETE_TIME_SECONDS", 30))
        self.time_per_char = float(os.getenv("TIME_PER_CHARACTER_SECONDS", 0.5))
        self.max_lifetime = int(os.getenv("MAX_MESSAGE_LIFETIME_SECONDS", 300))
        self.cleanup_interval = int(os.getenv("CLEANUP_INTERVAL_SECONDS", 5))
        self.inactivity_timeout = int(os.getenv("INACTIVITY_TIMEOUT_SECONDS", 30))
        
        # Meddelandelagring - OrderedDict för FIFO och effektiv radering
        self._messages: OrderedDict[str, Message] = OrderedDict()
        
        # Användarsessioner
        self._sessions: Dict[int, UserSession] = {}
        
        # Callbacks för notifieringar
        self._on_message_deleted: Optional[Callable] = None
        self._on_status_change: Optional[Callable] = None
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        print(f"📦 MessageStore initierad:")
        print(f"   - Bas raderingstid: {self.base_delete_time}s")
        print(f"   - Tid per tecken: {self.time_per_char}s")
        print(f"   - Max livstid: {self.max_lifetime}s")
        print(f"   - Cleanup interval: {self.cleanup_interval}s")
    
    def set_callbacks(self, on_deleted: Callable, on_status: Callable):
        """Sätt callbacks för händelser"""
        self._on_message_deleted = on_deleted
        self._on_status_change = on_status
    
    async def start_cleanup_task(self):
        """Starta bakgrundsuppgift för att rensa gamla meddelanden"""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        print("🧹 Cleanup task startad")
    
    async def stop_cleanup_task(self):
        """Stoppa bakgrundsuppgiften"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        print("🛑 Cleanup task stoppad")
    
    async def _cleanup_loop(self):
        """Loop som regelbundet rensar utgångna meddelanden"""
        while self._running:
            try:
                await self._cleanup_expired_messages()
                await self._check_inactive_users()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"❌ Cleanup fel: {e}")
                await asyncio.sleep(self.cleanup_interval)
    
    async def _cleanup_expired_messages(self):
        """Radera meddelanden som har passerat sin delete_at tid"""
        now = datetime.utcnow()
        to_delete = []
        
        for msg_id, msg in self._messages.items():
            if msg.delete_at and now >= msg.delete_at:
                to_delete.append(msg_id)
        
        for msg_id in to_delete:
            msg = self._messages.pop(msg_id, None)
            if msg and self._on_message_deleted:
                await self._on_message_deleted(msg_id, msg.sender_id, msg.receiver_id)
                print(f"🗑️  Meddelande {msg_id[:8]}... raderat automatiskt")
    
    async def _check_inactive_users(self):
        """Kontrollera och uppdatera inaktiva användare"""
        now = datetime.utcnow()
        timeout = timedelta(seconds=self.inactivity_timeout)
        
        for user_id, session in self._sessions.items():
            if session.status == UserStatus.ONLINE:
                if now - session.last_activity > timeout:
                    session.status = UserStatus.AWAY
                    if self._on_status_change:
                        await self._on_status_change(user_id, UserStatus.AWAY)
    
    def calculate_delete_time(self, char_count: int) -> datetime:
        """Beräkna när ett meddelande ska raderas baserat på antal tecken"""
        extra_time = char_count * self.time_per_char
        total_time = min(self.base_delete_time + extra_time, self.max_lifetime)
        return datetime.utcnow() + timedelta(seconds=total_time)
    
    def add_message(
        self,
        sender_id: int,
        receiver_id: int,
        content: str,
        message_type: MessageType = MessageType.TEXT
    ) -> Message:
        """Lägg till ett nytt meddelande"""
        # Räkna tecken innan kryptering
        char_count = len(content)
        
        # Kryptera innehållet
        encrypted_content = encrypt_message(content)
        
        msg = Message(
            id=str(uuid.uuid4()),
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=encrypted_content,
            message_type=message_type,
            status=MessageStatus.SENT,
            created_at=datetime.utcnow(),
            char_count=char_count
        )
        
        self._messages[msg.id] = msg
        print(f"📨 Meddelande {msg.id[:8]}... sparat ({char_count} tecken)")
        return msg
    
    def get_message(self, message_id: str) -> Optional[Message]:
        """Hämta ett meddelande"""
        return self._messages.get(message_id)
    
    def get_decrypted_content(self, message_id: str) -> Optional[str]:
        """Hämta dekrypterat innehåll för ett meddelande"""
        msg = self._messages.get(message_id)
        if msg:
            return decrypt_message(msg.content)
        return None
    
    def mark_as_delivered(self, message_id: str) -> bool:
        """Markera meddelande som levererat"""
        msg = self._messages.get(message_id)
        if msg and msg.status == MessageStatus.SENT:
            msg.status = MessageStatus.DELIVERED
            return True
        return False
    
    def mark_as_read(self, message_id: str) -> Optional[Message]:
        """Markera meddelande som läst och starta raderingstimer"""
        msg = self._messages.get(message_id)
        if msg and msg.status in [MessageStatus.SENT, MessageStatus.DELIVERED]:
            msg.status = MessageStatus.READ
            msg.read_at = datetime.utcnow()
            msg.delete_at = self.calculate_delete_time(msg.char_count)
            msg.status = MessageStatus.PENDING_DELETE
            
            time_until_delete = (msg.delete_at - datetime.utcnow()).total_seconds()
            print(f"👁️  Meddelande {message_id[:8]}... läst, raderas om {time_until_delete:.1f}s")
            return msg
        return None
    
    def get_messages_for_user(self, user_id: int) -> List[dict]:
        """Hämta alla meddelanden för en användare (dekrypterade)"""
        messages = []
        for msg in self._messages.values():
            if msg.sender_id == user_id or msg.receiver_id == user_id:
                messages.append({
                    "id": msg.id,
                    "sender_id": msg.sender_id,
                    "sender_name": USERS.get(msg.sender_id, {}).get("name", "unknown"),
                    "receiver_id": msg.receiver_id,
                    "content": decrypt_message(msg.content),
                    "message_type": msg.message_type.value,
                    "status": msg.status.value,
                    "created_at": msg.created_at.isoformat(),
                    "char_count": msg.char_count
                })
        return messages
    
    def get_unread_messages(self, user_id: int) -> List[dict]:
        """Hämta olästa meddelanden för en användare"""
        return [
            m for m in self.get_messages_for_user(user_id)
            if m["receiver_id"] == user_id and m["status"] in ["sent", "delivered"]
        ]
    
    def clear_all_messages(self) -> int:
        """Radera alla meddelanden. Returnerar antal raderade."""
        count = len(self._messages)
        self._messages.clear()
        print(f"🧹 Alla {count} meddelanden raderade")
        return count
    
    # Session hantering
    def create_session(self, user_id: int) -> Optional[UserSession]:
        """Skapa en session för en användare"""
        if user_id not in USERS:
            return None
        
        session = UserSession(
            user_id=user_id,
            user_name=USERS[user_id]["name"],
            status=UserStatus.ONLINE,
            last_activity=datetime.utcnow(),
            is_tab_active=True
        )
        self._sessions[user_id] = session
        return session
    
    def get_session(self, user_id: int) -> Optional[UserSession]:
        """Hämta session för en användare"""
        return self._sessions.get(user_id)
    
    def update_activity(self, user_id: int):
        """Uppdatera senaste aktivitet för en användare"""
        session = self._sessions.get(user_id)
        if session:
            session.last_activity = datetime.utcnow()
            if session.status == UserStatus.AWAY:
                session.status = UserStatus.ONLINE
    
    def set_tab_visibility(self, user_id: int, is_active: bool):
        """Sätt flikens synlighet för en användare"""
        session = self._sessions.get(user_id)
        if session:
            session.is_tab_active = is_active
            session.status = UserStatus.ONLINE if is_active else UserStatus.AWAY
            session.last_activity = datetime.utcnow()
    
    def remove_session(self, user_id: int):
        """Ta bort en session"""
        if user_id in self._sessions:
            del self._sessions[user_id]
            print(f"👋 Session för användare {user_id} avslutad")
    
    def get_active_session_count(self) -> int:
        """Räkna aktiva sessioner"""
        return len(self._sessions)
    
    def is_session_available(self) -> bool:
        """Kontrollera om det finns plats för fler sessioner"""
        return self.get_active_session_count() < 2
    
    def get_other_user_status(self, user_id: int) -> Optional[dict]:
        """Hämta status för den andra användaren"""
        other_id = 2 if user_id == 1 else 1
        session = self._sessions.get(other_id)
        if session:
            return {
                "user_id": other_id,
                "user_name": session.user_name,
                "status": session.status.value,
                "is_tab_active": session.is_tab_active
            }
        return {
            "user_id": other_id,
            "user_name": USERS[other_id]["name"],
            "status": UserStatus.OFFLINE.value,
            "is_tab_active": False
        }
    
    def get_stats(self) -> dict:
        """Hämta statistik för debugging"""
        return {
            "total_messages": len(self._messages),
            "active_sessions": self.get_active_session_count(),
            "sessions": {
                uid: {
                    "name": s.user_name,
                    "status": s.status.value,
                    "tab_active": s.is_tab_active
                }
                for uid, s in self._sessions.items()
            }
        }

# Singleton instans
store = MessageStore()