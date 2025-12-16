from pydantic import BaseModel
from typing import Optional, Literal
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

class UserStatus(str, Enum):
    ONLINE = "online"
    AWAY = "away"
    OFFLINE = "offline"

# Användarinfo - minimal data
USERS = {
    1: {"id": 1, "name": "poosie"},
    2: {"id": 2, "name": "noosie"}
}

class Message(BaseModel):
    id: str
    sender_id: int
    receiver_id: int
    content: str  # Krypterat innehåll
    message_type: MessageType
    status: MessageStatus = MessageStatus.SENT
    created_at: datetime
    read_at: Optional[datetime] = None
    delete_at: Optional[datetime] = None
    char_count: int = 0  # För att beräkna raderingstid

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
        "session_full"       # Sessionen är full
    ]
    data: dict

class OutgoingMessage(BaseModel):
    """Format för utgående meddelanden till klienten"""
    id: str
    sender_id: int
    sender_name: str
    receiver_id: int
    content: str  # Dekrypterat för mottagaren
    message_type: MessageType
    status: MessageStatus
    created_at: str
    char_count: int