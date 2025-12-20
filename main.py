import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from config import config
from models import (
    MessageType, MessageStatus, UserStatus, USERS,
    WebSocketMessage, TokenResponse, LoginRequest, LastSeenResponse
)
from message_store import store
from encryption import encryption
from session_tracker import tracker, DeviceStatus
from last_seen_store import last_seen_store
from cleanup_tasks import cleanup_scheduler
from session_manager import active_session_manager

# Aktiva WebSocket-anslutningar
active_connections: Dict[int, WebSocket] = {}
pending_connections: Dict[int, WebSocket] = {}

# Security
security = HTTPBearer()

# ============ JWT FUNCTIONS ============

def create_access_token(user_id: int) -> tuple[str, str]:
    """
    Skapa JWT access token med JTI (JWT ID).
    Returnerar (token, jti)
    """
    expires = datetime.utcnow() + timedelta(hours=config.JWT_EXPIRATION_HOURS)
    
    # Skapa unikt JTI (JWT ID)
    import uuid
    jti = str(uuid.uuid4())
    
    payload = {
        "user_id": user_id,
        "jti": jti,  # JWT Token ID för att identifiera denna specifika token
        "exp": expires
    }
    token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    
    # ✅ FIXAT: Registrera sessionen med JTI (inte token!)
    active_session_manager.create_session(user_id, jti)
    
    return token, jti

def verify_token(token: str) -> Optional[int]:
    """
    Verifiera JWT token och kontrollera att sessionen är aktiv.
    Returnerar user_id om giltig, annars None.
    """
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        user_id = payload.get("user_id")
        jti = payload.get("jti")
        
        if not user_id or user_id not in USERS:
            return None
        
        if not jti:
            print("⚠️  Token saknar JTI")
            return None
        
        # Kontrollera att detta är den aktiva sessionen för användaren
        if not active_session_manager.is_valid_session(user_id, jti):
            print(f"⛔ Session är inte längre aktiv för användare {user_id}")
            return None
        
        return user_id
        
    except jwt.ExpiredSignatureError:
        print("⚠️  Token har gått ut")
        return None
    except jwt.InvalidTokenError:
        print("⚠️  Ogiltig token")
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """Hämta nuvarande användare från JWT token"""
    user_id = verify_token(credentials.credentials)
    if not user_id:
        raise HTTPException(status_code=401, detail="Ogiltig eller utgången token")
    return user_id

# ============ CALLBACKS ============

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

# ============ LIFESPAN ============

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Hantera uppstart och nedstängning"""
    # Validera konfiguration
    config.validate()
    config.print_config()
    
    # Starta services
    store.set_callbacks(on_message_deleted, on_status_change)
    await store.start_cleanup_task()
    cleanup_scheduler.start()
    
    print("🚀 WebSocket Chat Server startad!")
    
    yield
    
    # Stoppa services
    await store.stop_cleanup_task()
    cleanup_scheduler.stop()
    print("👋 Server stängs ner...")

# ============ APP SETUP ============

app = FastAPI(
    title="Private WebSocket Chat (Secure)",
    description="End-to-end encrypted chat for 2 users with JWT auth",
    version="2.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ UTILITY FUNCTIONS ============

def get_client_ip(request: Request) -> str:
    """Hämta klientens IP-adress"""
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
    parts = authorization.split(" ")
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return tracker.verify_token(parts[1])
    return tracker.verify_token(authorization)

# ============ AUTH ENDPOINTS ============
@app.post("/api/auth/login", response_model=TokenResponse)
async def login(request: Request, login_data: LoginRequest):
    """
    Login endpoint - genererar JWT token.
    Om användaren redan är ansluten via WebSocket:
    1. Rensa alla meddelanden
    2. Skicka security breach till gamla anslutningen
    3. Stäng gamla anslutningen
    4. Skapa ny session
    """
    user_id = login_data.user_id
    
    if user_id not in USERS:
        raise HTTPException(status_code=401, detail="Ogiltig användare")
    
    # Logga session
    user_agent = request.headers.get("user-agent", "unknown")
    ip_address = get_client_ip(request)
    
    if user_id == 1:
        tracker.log_session(user_id, ip_address, user_agent)
        tracker.increment_login_count(user_id)
    
    # 🚨 KRITISKT: Kolla om användaren redan är ansluten
    is_already_connected = user_id in active_connections
    
    if is_already_connected:
        print(f"🚨 SÄKERHETSBRIST: Användare {user_id} försöker logga in medan redan ansluten!")
        
        # 1. Rensa alla meddelanden FÖRST (innan någon ny anslutning)
        cleared_count = store.clear_all_messages()
        print(f"🧹 Rensade {cleared_count} meddelanden pga dubbel inloggning")
        
        # 2. Skicka security breach till gamla anslutningen
        await close_existing_connection(user_id, reason="security_breach")
        
        # 3. Vänta lite extra så gamla anslutningen hinner stängas
        await asyncio.sleep(1)
    
    # Skapa token (invaliderar automatiskt gamla sessioner)
    token, jti = create_access_token(user_id)
    
    print(f"✅ Användare {user_id} inloggad från {ip_address} (JTI: {jti[:8]}...)")
    
    # Returnera med flagga om det var dubbel inloggning
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=config.JWT_EXPIRATION_HOURS * 3600,
        # Lägg till extra data i response (behöver uppdatera TokenResponse model)
    )

@app.post("/api/auth/verify")
async def verify_auth(user_id: int = Depends(get_current_user)):
    """Verifiera att token är giltig"""
    return {
        "valid": True,
        "user_id": user_id,
        "user_name": USERS[user_id]["name"]
    }

@app.post("/api/auth/logout")
async def logout(user_id: int = Depends(get_current_user)):
    """
    Logga ut och invalidera session.
    Detta gör att token inte längre är giltig.
    """
    active_session_manager.invalidate_session(user_id)
    
    print(f"👋 Användare {user_id} loggade ut")
    
    return {
        "success": True,
        "message": "Utloggad"
    }

# ============ LAST SEEN ENDPOINTS ============

@app.get("/api/last-seen/{user_id}", response_model=LastSeenResponse)
async def get_last_seen(user_id: int):
    """Hämta last seen för en användare"""
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="Användare hittades inte")
    
    data = last_seen_store.get_last_seen(user_id, decrypt=False)
    
    # Kolla om användaren är online just nu
    is_online = user_id in active_connections
    
    if not data:
        return LastSeenResponse(
            user_id=user_id,
            last_seen_at=datetime.utcnow().isoformat(),
            last_seen_ago="Aldrig sedd",
            is_online=is_online
        )
    
    return LastSeenResponse(
        user_id=user_id,
        last_seen_at=data["last_seen_at"],
        last_seen_ago=data["last_seen_ago"] if not is_online else "Online nu",
        is_online=is_online
    )

@app.get("/api/last-seen")
async def get_all_last_seen():
    """Hämta last seen för alla användare"""
    data = last_seen_store.get_all_last_seen(decrypt=False)
    
    result = {}
    for user_id in USERS.keys():
        is_online = user_id in active_connections
        user_data = data.get(user_id)
        
        if user_data:
            result[user_id] = {
                **user_data,
                "user_name": USERS[user_id]["name"],
                "is_online": is_online,
                "last_seen_ago": "Online nu" if is_online else user_data["last_seen_ago"]
            }
        else:
            result[user_id] = {
                "user_id": user_id,
                "user_name": USERS[user_id]["name"],
                "last_seen_at": None,
                "last_seen_ago": "Aldrig sedd",
                "is_online": is_online
            }
    
    return result

# ============ SESSION TRACKING ENDPOINTS ============

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
        raise HTTPException(status_code=400, detail="Invalid status")
    
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

# ============ WEBSOCKET HANDLERS ============

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
    
    # ✅ FIXAT: Dekryptera innehållet innan vi skickar till klienter
    decrypted_content = encryption.decrypt_message({
        "encrypted": msg.content.encrypted,
        "salt": msg.content.salt
    })
    
    outgoing = {
        "type": "chat_message",
        "data": {
            "id": msg.id,
            "sender_id": msg.sender_id,
            "sender_name": USERS[msg.sender_id]["name"],
            "receiver_id": msg.receiver_id,
            "content": decrypted_content,  # ✅ Skicka dekrypterat
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
    """
    Hantera rensning av alla meddelanden.
    Invaliderar också sessionen så användaren måste logga in igen.
    """
    count = store.clear_all_messages()
    
    # Invalidera sessionen - användaren måste logga in igen
    active_session_manager.invalidate_session(user_id)
    
    notification = {
        "type": "clear_all",
        "data": {
            "cleared_by": user_id,
            "cleared_by_name": USERS[user_id]["name"],
            "count": count,
            "session_invalidated": True  # Informera frontend att logga ut
        }
    }
    
    for uid in list(active_connections.keys()):
        await send_to_user(uid, notification)
    
    print(f"🧹 Användare {user_id} rensade chatten och invaliderade sessionen")

async def handle_heartbeat(user_id: int):
    """Hantera heartbeat för att hålla anslutningen vid liv"""
    store.update_activity(user_id)
    await send_to_user(user_id, {
        "type": "heartbeat",
        "data": {"timestamp": datetime.utcnow().isoformat()}
    })

async def close_existing_connection(user_id: int, reason: str = "new_connection"):
    """Stäng befintlig anslutning för en användare med security breach notis"""
    if user_id in active_connections:
        old_ws = active_connections[user_id]
        try:
            # Skicka security breach varning till den gamla anslutningen
            if reason == "security_breach":
                await old_ws.send_json({
                    "type": "security_breach",
                    "data": {
                        "message": "Säkerhetsbrist: Dubbla WebSocket-anslutningar",
                        "reason": "Någon försöker logga in på ditt konto samtidigt som du är inloggad"
                    }
                })
                # Vänta lite så meddelandet hinner fram
                await asyncio.sleep(0.5)
            
            await old_ws.close(code=4001, reason=reason)
        except Exception as e:
            print(f"⚠️ Kunde inte stänga gamla anslutningen: {e}")
        
        # Ta bort från active
        del active_connections[user_id]
        store.remove_session(user_id)
        print(f"🔄 Stängde gammal anslutning för användare {user_id} (reason: {reason})")
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """
    Huvudsaklig WebSocket endpoint med JWT-autentisering och security breach detektion.
    """
    
    # Verifiera token OCH att sessionen är aktiv
    user_id = verify_token(token)
    if not user_id:
        # 🚨 KRITISKT: Måste acceptera först innan vi kan stänga med custom code!
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "data": {"message": "Session invaliderad eller token utgången"}
        })
        await websocket.close(code=4001, reason="Invalid, expired or inactive session")
        print(f"⛔ WebSocket rejected - session invaliderad eller token utgången")
        return
    
    # 🔒 SÄKERHETSKONTROLL: Kolla om användaren redan är ansluten
    if user_id in active_connections:
        print(f"🚨 WebSocket security breach detected för användare {user_id}")
        
        # Acceptera tillfälligt för att skicka meddelande
        await websocket.accept()
        
        # Informera om security breach (denna är den NYA anslutningen)
        await websocket.send_json({
            "type": "duplicate_connection",
            "data": {
                "message": "Du är redan inloggad i en annan flik/enhet",
                "action": "redirect_to_task"
            }
        })
        
        # Stäng direkt
        await websocket.close(code=4002, reason="Duplicate connection detected")
        return
    
    # Kontrollera om sessionen är full
    other_user_id = 2 if user_id == 1 else 1
    if other_user_id in active_connections and len(active_connections) >= 2:
        await websocket.accept()
        await websocket.send_json({
            "type": "session_full",
            "data": {"message": "Chat session is full"}
        })
        await websocket.close(code=4003, reason="Session full")
        return
    
    # Acceptera anslutningen
    await websocket.accept()
    active_connections[user_id] = websocket
    store.create_session(user_id)
    
    # Uppdatera last seen
    ip_address = websocket.client.host if websocket.client else "unknown"
    user_agent = dict(websocket.headers).get("user-agent", "unknown")
    last_seen_store.update_last_seen(user_id, ip_address, user_agent)
    
    print(f"✅ Användare {USERS[user_id]['name']} (ID: {user_id}) ansluten")
    
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
                last_seen_store.update_last_seen(user_id, ip_address, user_agent)
                
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
            
            # Uppdatera last seen vid frånkoppling
            last_seen_store.update_last_seen(user_id, ip_address, user_agent)
            
            print(f"👋 Användare {USERS[user_id]['name']} (ID: {user_id}) frånkopplad")
            
            await broadcast_to_other(user_id, {
                "type": "user_disconnected",
                "data": {
                    "user_id": user_id,
                    "user_name": USERS[user_id]["name"]
                }
            })

# ============ REST ENDPOINTS ============

@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "WebSocket Chat Server (Secure)",
        "version": "2.0.0",
        "environment": config.ENVIRONMENT.value,
        "ssl_enabled": config.USE_SSL,
        "active_connections": list(active_connections.keys())
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "environment": config.ENVIRONMENT.value}

@app.get("/stats")
async def stats():
    return {
        **store.get_stats(),
        "active_ws_connections": list(active_connections.keys()),
        "active_sessions": active_session_manager.get_all_sessions(),
        "environment": config.ENVIRONMENT.value
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

# ============ MANUAL CLEANUP ENDPOINT (För testning) ============

@app.post("/api/admin/cleanup")
async def manual_cleanup(authorization: str = Header(None)):
    """Kör manuell cleanup (kräver token)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    await cleanup_scheduler.run_manual_cleanup()
    return {"status": "cleanup completed"}

@app.post("/api/admin/invalidate-session/{user_id}")
async def invalidate_user_session(user_id: int, authorization: str = Header(None)):
    """Invalidera session för en användare (admin only)"""
    if not verify_api_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")
    
    active_session_manager.invalidate_session(user_id)
    
    # Stäng även WebSocket-anslutningen om den finns
    if user_id in active_connections:
        try:
            await active_connections[user_id].close(code=4001, reason="Session invalidated by admin")
        except:
            pass
    
    return {
        "success": True,
        "message": f"Session invalidated for user {user_id}"
    }

if __name__ == "__main__":
    import uvicorn
    
    # Railway/Cloudflare hanterar SSL - kör vanlig HTTP lokalt
    # Railway's proxy lägger automatiskt på HTTPS
    uvicorn.run(
        app,
        host=config.HOST,
        port=config.PORT
    )