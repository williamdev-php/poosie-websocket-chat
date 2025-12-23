from pydantic import BaseModel
from typing import Optional, Literal, Dict
from datetime import datetime
from enum import Enum

class MessageType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    GIF = "gif"
    EMOJI = "emoji"
    SYSTEM = "system"

class MessageStatus(str, Enum):
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    PENDING_DELETE = "pending_delete"
    EDITED = "edited"  # 🆕 För redigerade meddelanden

class UserStatus(str, Enum):
    ONLINE = "online"
    AWAY = "away"
    OFFLINE = "offline"

# Användarinfo - minimal data
USERS = {
    1: {"id": 1, "name": "poosie"},
    2: {"id": 2, "name": "noosie"}
}

class EncryptedContent(BaseModel):
    """Krypterat innehåll med salt"""
    encrypted: str
    salt: str

class Message(BaseModel):
    id: str
    sender_id: int
    receiver_id: int
    content: EncryptedContent  # Krypterat innehåll med salt
    message_type: MessageType
    status: MessageStatus = MessageStatus.SENT
    created_at: datetime
    read_at: Optional[datetime] = None
    delete_at: Optional[datetime] = None
    char_count: int = 0  # För att beräkna raderingstid
    edited_at: Optional[datetime] = None  # 🆕 När meddelandet redigerades
    is_edited: bool = False  # 🆕 Flagga för redigerat
    queue_position: Optional[int] = None  # 🆕 Position i raderingskön

class UserSession(BaseModel):
    user_id: int
    user_name: str
    status: UserStatus = UserStatus.OFFLINE
    last_activity: datetime
    is_tab_active: bool = True

class WebSocketMessage(BaseModel):
    """Meddelanden som skickas via WebSocket"""
    type: Literal[
        "chat_message",      # Chattmeddelande
        "status_update",     # Användarstatus ändrad
        "message_read",      # Meddelande läst
        "typing",            # Användaren skriver
        "stop_typing",       # Användaren slutade skriva
        "tab_visibility",    # Flik synlighet ändrad
        "clear_all",         # Rensa alla meddelanden
        "heartbeat",         # Håll anslutningen vid liv
        "error",             # Felmeddelande
        "connection_info",   # Anslutningsinfo
        "user_connected",    # Användare anslöt
        "user_disconnected", # Användare frånkopplad
        "message_deleted",   # Meddelande raderat
        "session_full",      # Sessionen är full
        "security_breach",   # 🚨 Säkerhetsbrist (dubbel inloggning)
        "duplicate_connection",  # 🚨 Duplicate WebSocket connection
        "delete_message",    # 🆕 Radera meddelande manuellt
        "edit_message",      # 🆕 Redigera meddelande
        "message_edited",    # 🆕 Meddelande redigerat (notifiering)
        "force_logout"       # 🆕 Tvångsutloggning (admin stängde av login)
    ]
    data: dict

class OutgoingMessage(BaseModel):
    """Format för utgående meddelanden till klienten"""
    id: str
    sender_id: int
    sender_name: str
    receiver_id: int
    content: EncryptedContent  # Krypterat - frontend dekrypterar
    message_type: MessageType
    status: MessageStatus
    created_at: str
    char_count: int
    is_edited: bool = False  # 🆕
    edited_at: Optional[str] = None  # 🆕

# JWT Models
class TokenPayload(BaseModel):
    user_id: int
    exp: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class LoginRequest(BaseModel):
    user_id: int
    # I framtiden kan man lägga till password här

class LastSeenResponse(BaseModel):
    user_id: int
    last_seen_at: str
    last_seen_ago: str  # "2 timmar sedan"
    is_online: bool = False