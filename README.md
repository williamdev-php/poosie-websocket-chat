# 🔐 Private WebSocket Chat Server

En enkel, säker WebSocket-baserad chattserver för 2 användare med end-to-end kryptering och automatisk meddelanderadering.

## ✨ Funktioner

- **Max 2 användare**: Endast "poosie" (ID 1) och "noosie" (ID 2)
- **End-to-end kryptering**: Alla meddelanden krypteras med Fernet
- **Automatisk radering**: Meddelanden raderas baserat på längd efter läsning
- **Aktivitetsstatus**: Se om den andra användaren är aktiv
- **Flik-medvetenhet**: Status uppdateras vid flikbyte
- **RAM-lagring**: Ingen databas, allt i minnet
- **Stöd för**: Text, emojis, bilder (base64), GIFs

## 🚀 Snabbstart

### Lokal utveckling

```bash
# 1. Klona och navigera till projektet
cd websocket-chat

# 2. Skapa virtuell miljö
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate    # Windows

# 3. Installera dependencies
pip install -r requirements.txt

# 4. Konfigurera miljövariabler
cp .env.example .env
# Redigera .env och generera en krypteringsnyckel:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 5. Starta servern
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Deploy till Railway

1. Skapa konto på [railway.app](https://railway.app)
2. Skapa nytt projekt → "Deploy from GitHub repo"
3. Lägg till miljövariabler i Railway dashboard:
   - `ENCRYPTION_KEY` (generera med kommandot ovan)
   - Övriga variabler från `.env.example`
4. Railway deployer automatiskt!

## 📡 WebSocket API

### Anslutning

```
ws://localhost:8000/ws/{user_id}
```

- `user_id=1` → poosie
- `user_id=2` → noosie

### Meddelandeformat (JSON)

Alla meddelanden skickas som JSON med strukturen:
```json
{
  "type": "message_type",
  "data": { ... }
}
```

### Klient → Server

#### Skicka chattmeddelande
```json
{
  "type": "chat_message",
  "data": {
    "content": "Hej! 👋",
    "message_type": "text"  // "text", "image", "gif", "emoji"
  }
}
```

#### Skicka bild (base64)
```json
{
  "type": "chat_message",
  "data": {
    "content": "data:image/png;base64,iVBORw0KGgo...",
    "message_type": "image"
  }
}
```

#### Markera meddelande som läst
```json
{
  "type": "message_read",
  "data": {
    "message_id": "uuid-here"
  }
}
```

#### Skrivindikator
```json
{"type": "typing", "data": {}}
{"type": "stop_typing", "data": {}}
```

#### Fliksynlighet (för aktivitetsstatus)
```json
{
  "type": "tab_visibility",
  "data": {
    "is_active": false  // true när fliken är synlig
  }
}
```

#### Rensa alla meddelanden
```json
{"type": "clear_all", "data": {}}
```

#### Heartbeat (håll anslutningen vid liv)
```json
{"type": "heartbeat", "data": {}}
```

### Server → Klient

#### Vid anslutning (connection_info)
```json
{
  "type": "connection_info",
  "data": {
    "user_id": 1,
    "user_name": "poosie",
    "other_user": {
      "user_id": 2,
      "user_name": "noosie",
      "status": "offline",
      "is_tab_active": false
    },
    "messages": [...],
    "unread_count": 0
  }
}
```

#### Nytt chattmeddelande
```json
{
  "type": "chat_message",
  "data": {
    "id": "msg-uuid",
    "sender_id": 2,
    "sender_name": "noosie",
    "receiver_id": 1,
    "content": "Hallå!",
    "message_type": "text",
    "status": "delivered",
    "created_at": "2024-01-15T10:30:00",
    "char_count": 6
  }
}
```

#### Statusuppdatering
```json
{
  "type": "status_update",
  "data": {
    "user_id": 2,
    "user_name": "noosie",
    "status": "online"  // "online", "away", "offline"
  }
}
```

#### Meddelande läst
```json
{
  "type": "message_read",
  "data": {
    "message_id": "uuid",
    "read_at": "2024-01-15T10:31:00",
    "delete_at": "2024-01-15T10:32:30"
  }
}
```

#### Meddelande raderat
```json
{
  "type": "message_deleted",
  "data": {
    "message_id": "uuid"
  }
}
```

#### Session full
```json
{
  "type": "session_full",
  "data": {
    "message": "Chat session is full. Max 2 users allowed."
  }
}
```

## 🛠️ Konfiguration (.env)

| Variabel | Default | Beskrivning |
|----------|---------|-------------|
| `BASE_DELETE_TIME_SECONDS` | 30 | Bas-tid innan radering |
| `TIME_PER_CHARACTER_SECONDS` | 0.5 | Extra tid per tecken |
| `MAX_MESSAGE_LIFETIME_SECONDS` | 300 | Max livstid (5 min) |
| `CLEANUP_INTERVAL_SECONDS` | 5 | Hur ofta cleanup körs |
| `INACTIVITY_TIMEOUT_SECONDS` | 30 | Tid till "away" status |
| `ENCRYPTION_KEY` | - | **Krävs!** Fernet-nyckel |

### Raderingsformel

```
delete_time = BASE_DELETE_TIME + (char_count × TIME_PER_CHARACTER)
delete_time = min(delete_time, MAX_MESSAGE_LIFETIME)
```

Exempel med default-värden:
- "Hej" (3 tecken) → 30 + (3 × 0.5) = 31.5 sekunder
- "Lång text..." (100 tecken) → 30 + (100 × 0.5) = 80 sekunder

## 🔌 REST Endpoints

| Endpoint | Metod | Beskrivning |
|----------|-------|-------------|
| `/` | GET | Hälsokontroll |
| `/health` | GET | Health check för Railway |
| `/stats` | GET | Debug statistik |
| `/users` | GET | Lista användare |

## 🎯 React/Next.js Integration

```typescript
// hooks/useWebSocket.ts
import { useEffect, useRef, useState, useCallback } from 'react';

interface Message {
  id: string;
  sender_id: number;
  sender_name: string;
  content: string;
  message_type: string;
  status: string;
  created_at: string;
}

export function useChat(userId: 1 | 2) {
  const ws = useRef<WebSocket | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [otherUser, setOtherUser] = useState<any>(null);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';
    ws.current = new WebSocket(`${WS_URL}/ws/${userId}`);

    ws.current.onopen = () => setIsConnected(true);
    ws.current.onclose = () => setIsConnected(false);
    
    ws.current.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      
      switch (msg.type) {
        case 'connection_info':
          setMessages(msg.data.messages);
          setOtherUser(msg.data.other_user);
          break;
        case 'chat_message':
          setMessages(prev => [...prev, msg.data]);
          break;
        case 'status_update':
          setOtherUser(prev => ({ ...prev, ...msg.data }));
          break;
        case 'message_deleted':
          setMessages(prev => prev.filter(m => m.id !== msg.data.message_id));
          break;
        case 'clear_all':
          setMessages([]);
          break;
      }
    };

    // Tab visibility
    const handleVisibility = () => {
      ws.current?.send(JSON.stringify({
        type: 'tab_visibility',
        data: { is_active: !document.hidden }
      }));
    };
    document.addEventListener('visibilitychange', handleVisibility);

    // Heartbeat
    const heartbeat = setInterval(() => {
      ws.current?.send(JSON.stringify({ type: 'heartbeat', data: {} }));
    }, 30000);

    return () => {
      clearInterval(heartbeat);
      document.removeEventListener('visibilitychange', handleVisibility);
      ws.current?.close();
    };
  }, [userId]);

  const sendMessage = useCallback((content: string, type = 'text') => {
    ws.current?.send(JSON.stringify({
      type: 'chat_message',
      data: { content, message_type: type }
    }));
  }, []);

  const markAsRead = useCallback((messageId: string) => {
    ws.current?.send(JSON.stringify({
      type: 'message_read',
      data: { message_id: messageId }
    }));
  }, []);

  const clearAll = useCallback(() => {
    ws.current?.send(JSON.stringify({ type: 'clear_all', data: {} }));
  }, []);

  return { messages, otherUser, isConnected, sendMessage, markAsRead, clearAll };
}
```

## 📦 Projektstruktur

```
websocket-chat/
├── main.py              # FastAPI WebSocket server
├── models.py            # Pydantic modeller
├── message_store.py     # RAM-lagring med auto-radering
├── encryption.py        # Fernet kryptering
├── requirements.txt     
├── .env.example         
├── Procfile             # Railway
├── railway.json         
└── README.md
```

## 🔒 Säkerhet

- Alla meddelanden krypteras med Fernet (AES-128-CBC)
- Meddelanden raderas automatiskt efter läsning
- Ingen persistent lagring
- Max 2 samtidiga anslutningar

## 📝 Licens

MIT