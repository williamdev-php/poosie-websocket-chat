import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from models import (
    MessageType, MessageStatus, UserStatus, USERS,
    WebSocketMessage
)
from message_store import store
from encryption import decrypt_message
from session_tracker import tracker, DeviceStatus

load_dotenv()

# Aktiva WebSocket-anslutningar
active_connections: Dict[int, WebSocket] = {}

async def on_message_deleted(message_id: str, sender_id: int, receiver_id: int):
    """Callback när ett meddelande raderas automatiskt"""
    notification = {
        "type": "message_deleted",
        "data": {"message_id": message_id}
    }
    for user_id in [sender_id, receiver_id]:
        if user_id in active_connections:
            try:
                await active_connections[user_id].send_json(notification)
            except Exception:
                pass

async def on_status_change(user_id: int, status: UserStatus):
    """Callback när en användares status ändras"""
    other_id = 2 if user_id == 1 else 1
    if other_id in active_connections:
        try:
            await active_connections[other_id].send_json({
                "type": "status_update",
                "data": {
                    "user_id": user_id,
                    "user_name": USERS[user_id]["name"],
                    "status": status.value
                }
            })
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Hantera uppstart och nedstängning"""
    store.set_callbacks(on_message_deleted, on_status_change)
    await store.start_cleanup_task()
    print("🚀 WebSocket Chat Server startad!")
    yield
    await store.stop_cleanup_task()
    print("👋 Server stängs ner...")

app = FastAPI(
    title="Private WebSocket Chat",
    description="End-to-end encrypted chat for 2 users",
    version="1.0.0",
    lifespan=lifespan
)

# CORS för att tillåta frontend-anslutningar
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_client_ip(request: Request) -> str:
    """Hämta klientens IP-adress"""
    # Kolla headers för proxy/load balancer
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"

def verify_api_token(authorization: str = Header(None)) -> bool:
    """Verifiera API token från Authorization header"""
    if not authorization:
        return False
    # Förväntar "Bearer <token>"
    parts = authorization.split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return tracker.verify_token(parts[1])
    return tracker.verify_token(authorization)

# ============ SESSION TRACKING ENDPOINTS ============

@app.post("/api/session/log")
async def log_session(request: Request):
    """Logga en ny session (kallas vid inloggning för user_id 1)"""
    body = await request.json()
    user_id = body.get("user_id", 1)
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = get_client_ip(request)
    
    session = tracker.log_session(user_id, ip_address, user_agent)
    
    # Öka login count för onboarding
    if user_id == 1:
        tracker.increment_login_count(user_id)
    
    return session

@app.post("/api/session/check")
async def check_session(request: Request):
    """Kontrollera om en session är tillåten"""
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = get_client_ip(request)
    
    result = tracker.check_device_status(ip_address, user_agent)
    return result

@app.get("/api/sessions")
async def get_sessions(authorization: str = Header(None)):
    """Hämta alla sessioner (kräver token, endast user_id 2)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return {
        "sessions": tracker.get_all_sessions(),
        "total": len(tracker.get_all_sessions())
    }

@app.get("/api/sessions/anomalies")
async def get_anomalies(authorization: str = Header(None)):
    """Hämta sessioner med avvikelser (kräver token)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    anomalies = tracker.get_anomalies()
    return {
        "anomalies": anomalies,
        "count": len(anomalies)
    }

@app.get("/api/devices")
async def get_devices(authorization: str = Header(None)):
    """Hämta alla markerade enheter (kräver token)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return tracker.get_trusted_devices()

@app.post("/api/device/mark")
async def mark_device(request: Request, authorization: str = Header(None)):
    """Markera en enhet som trusted/blocked (kräver token)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    body = await request.json()
    fingerprint = body.get("fingerprint")
    status_str = body.get("status", "trusted")
    note = body.get("note")
    
    if not fingerprint:
        raise HTTPException(status_code=400, detail="fingerprint required")
    
    try:
        status = DeviceStatus(status_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status. Use: trusted, blocked, unknown")
    
    result = tracker.mark_device(fingerprint, status, marked_by=2, note=note)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return result

# ============ ONBOARDING ENDPOINTS ============

@app.get("/api/onboarding/{user_id}")
async def get_onboarding(user_id: int):
    """Hämta onboarding-status"""
    return {
        "should_show": tracker.should_show_onboarding(user_id),
        "status": tracker.get_onboarding_status(user_id)
    }

@app.post("/api/onboarding/{user_id}/dismiss")
async def dismiss_onboarding(user_id: int):
    """Stäng av onboarding permanent"""
    result = tracker.dismiss_onboarding(user_id)
    return {
        "success": True,
        "status": result
    }

# ============ DEVICE INFO ENDPOINT ============

@app.get("/api/device-info")
async def get_device_info(request: Request):
    """Hämta information om nuvarande enhet"""
    from session_tracker import parse_user_agent, generate_fingerprint
    
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = get_client_ip(request)
    parsed = parse_user_agent(user_agent)
    fingerprint = generate_fingerprint(ip_address, user_agent)
    
    # Kolla om enheten är markerad
    device_status = tracker.check_device_status(ip_address, user_agent)
    
    return {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "browser": parsed["browser"],
        "os": parsed["os"],
        "device_type": parsed["device_type"],
        "fingerprint": fingerprint,
        "status": device_status["status"],
        "is_anomaly": device_status["is_anomaly"]
    }

# ============ WEBSOCKET & CHAT HANDLERS ============

async def broadcast_to_other(sender_id: int, message: dict):
    """Skicka meddelande till den andra användaren"""
    other_id = 2 if sender_id == 1 else 1
    if other_id in active_connections:
        try:
            await active_connections[other_id].send_json(message)
        except Exception as e:
            print(f"❌ Kunde inte skicka till användare {other_id}: {e}")

async def send_to_user(user_id: int, message: dict):
    """Skicka meddelande till en specifik användare"""
    if user_id in active_connections:
        try:
            await active_connections[user_id].send_json(message)
        except Exception as e:
            print(f"❌ Kunde inte skicka till användare {user_id}: {e}")

async def handle_chat_message(user_id: int, data: dict):
    """Hantera inkommande chattmeddelande"""
    content = data.get("content", "")
    msg_type_str = data.get("message_type", "text")
    
    try:
        msg_type = MessageType(msg_type_str)
    except ValueError:
        msg_type = MessageType.TEXT
    
    receiver_id = 2 if user_id == 1 else 1
    
    msg = store.add_message(
        sender_id=user_id,
        receiver_id=receiver_id,
        content=content,
        message_type=msg_type
    )
    
    outgoing = {
        "type": "chat_message",
        "data": {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": USERS[msg.sender_id]["name"],
            "receiver_id": msg.receiver_id,
            "content": content,
            "message_type": msg.message_type.value,
            "status": msg.status.value,
            "created_at": msg.created_at.isoformat(),
            "char_count": msg.char_count
        }
    }
    
    await send_to_user(user_id, outgoing)
    
    if receiver_id in active_connections:
        store.mark_as_delivered(msg.id)
        outgoing["data"]["status"] = MessageStatus.DELIVERED.value
        await send_to_user(receiver_id, outgoing)

async def handle_message_read(user_id: int, data: dict):
    """Hantera när ett meddelande lästs"""
    message_id = data.get("message_id")
    if not message_id:
        return
    
    msg = store.mark_as_read(message_id)
    if msg:
        notification = {
            "type": "message_read",
            "data": {
                "message_id": message_id,
                "read_at": msg.read_at.isoformat() if msg.read_at else None,
                "delete_at": msg.delete_at.isoformat() if msg.delete_at else None
            }
        }
        await broadcast_to_other(user_id, notification)

async def handle_typing(user_id: int, is_typing: bool):
    """Hantera skrivindikator"""
    await broadcast_to_other(user_id, {
        "type": "typing" if is_typing else "stop_typing",
        "data": {
            "user_id": user_id,
            "user_name": USERS[user_id]["name"]
        }
    })

async def handle_tab_visibility(user_id: int, data: dict):
    """Hantera när användaren byter flik"""
    is_active = data.get("is_active", False)
    store.set_tab_visibility(user_id, is_active)
    
    status = UserStatus.ONLINE if is_active else UserStatus.AWAY
    await broadcast_to_other(user_id, {
        "type": "status_update",
        "data": {
            "user_id": user_id,
            "user_name": USERS[user_id]["name"],
            "status": status.value,
            "is_tab_active": is_active
        }
    })

async def handle_clear_all(user_id: int):
    """Hantera rensning av alla meddelanden"""
    count = store.clear_all_messages()
    
    notification = {
        "type": "clear_all",
        "data": {
            "cleared_by": user_id,
            "cleared_by_name": USERS[user_id]["name"],
            "count": count
        }
    }
    
    for uid in list(active_connections.keys()):
        await send_to_user(uid, notification)

async def handle_heartbeat(user_id: int):
    """Hantera heartbeat för att hålla anslutningen vid liv"""
    store.update_activity(user_id)
    await send_to_user(user_id, {
        "type": "heartbeat",
        "data": {"timestamp": datetime.utcnow().isoformat()}
    })

async def close_existing_connection(user_id: int):
    """Stäng befintlig anslutning för en användare"""
    if user_id in active_connections:
        old_ws = active_connections[user_id]
        try:
            await old_ws.close(code=4001, reason="New connection opened")
        except Exception:
            pass
        del active_connections[user_id]
        store.remove_session(user_id)
        print(f"🔄 Stängde gammal anslutning för användare {user_id}")

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """Huvudsaklig WebSocket endpoint"""
    
    # Validera user_id
    if user_id not in [1, 2]:
        await websocket.close(code=4001, reason="Invalid user ID")
        return
    
    # Stäng befintlig anslutning om den finns
    await close_existing_connection(user_id)
    
    # Kontrollera om sessionen är full
    other_user_id = 2 if user_id == 1 else 1
    if other_user_id in active_connections and len(active_connections) >= 2:
        await websocket.accept()
        await websocket.send_json({
            "type": "session_full",
            "data": {"message": "Chat session is full. Max 2 users allowed."}
        })
        await websocket.close(code=4003, reason="Session full")
        return
    
    # Acceptera anslutningen
    await websocket.accept()
    active_connections[user_id] = websocket
    store.create_session(user_id)
    
    print(f"✅ Användare {USERS[user_id]['name']} (ID: {user_id}) ansluten")
    print(f"📊 Aktiva anslutningar: {list(active_connections.keys())}")
    
    # Skicka initial info
    await websocket.send_json({
        "type": "connection_info",
        "data": {
            "user_id": user_id,
            "user_name": USERS[user_id]["name"],
            "other_user": store.get_other_user_status(user_id),
            "messages": store.get_messages_for_user(user_id),
            "unread_count": len(store.get_unread_messages(user_id))
        }
    })
    
    # Notifiera den andra användaren
    await broadcast_to_other(user_id, {
        "type": "user_connected",
        "data": {
            "user_id": user_id,
            "user_name": USERS[user_id]["name"],
            "status": UserStatus.ONLINE.value
        }
    })
    
    try:
        while True:
            raw_data = await websocket.receive_text()
            
            try:
                message = json.loads(raw_data)
                msg_type = message.get("type", "")
                data = message.get("data", {})
                
                store.update_activity(user_id)
                
                if msg_type == "chat_message":
                    await handle_chat_message(user_id, data)
                elif msg_type == "message_read":
                    await handle_message_read(user_id, data)
                elif msg_type == "typing":
                    await handle_typing(user_id, True)
                elif msg_type == "stop_typing":
                    await handle_typing(user_id, False)
                elif msg_type == "tab_visibility":
                    await handle_tab_visibility(user_id, data)
                elif msg_type == "clear_all":
                    await handle_clear_all(user_id)
                elif msg_type == "heartbeat":
                    await handle_heartbeat(user_id)
                else:
                    await websocket.send_json({
                        "type": "error",
                        "data": {"message": f"Unknown message type: {msg_type}"}
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": "Invalid JSON format"}
                })
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"❌ WebSocket fel för användare {user_id}: {e}")
    finally:
        if user_id in active_connections and active_connections[user_id] == websocket:
            del active_connections[user_id]
            store.remove_session(user_id)
            
            print(f"👋 Användare {USERS[user_id]['name']} (ID: {user_id}) frånkopplad")
            print(f"📊 Aktiva anslutningar: {list(active_connections.keys())}")
            
            await broadcast_to_other(user_id, {
                "type": "user_disconnected",
                "data": {
                    "user_id": user_id,
                    "user_name": USERS[user_id]["name"]
                }
            })

# REST endpoints
@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "WebSocket Chat Server",
        "version": "1.0.0",
        "active_connections": list(active_connections.keys())
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/stats")
async def stats():
    return {
        **store.get_stats(),
        "active_ws_connections": list(active_connections.keys())
    }

@app.get("/users")
async def get_users():
    return {
        "users": [
            {"id": 1, "name": "poosie", "connected": 1 in active_connections},
            {"id": 2, "name": "noosie", "connected": 2 in active_connections}
        ],
        "active_sessions": store.get_active_session_count(),
        "max_sessions": 2
    }

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host=host, port=port)