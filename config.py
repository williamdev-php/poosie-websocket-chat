import os
from enum import Enum
from dotenv import load_dotenv

load_dotenv()

class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"

class Config:
    """Central configuration with environment-based settings"""
    
    # Environment
    ENVIRONMENT = Environment(os.getenv("ENVIRONMENT", "development"))
    IS_PRODUCTION = ENVIRONMENT == Environment.PRODUCTION
    IS_DEVELOPMENT = ENVIRONMENT == Environment.DEVELOPMENT
    
    # Server
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8080))
    
    # SSL/TLS - Railway & Cloudflare hanterar detta!
    # Ingen manuell SSL-konfiguration behövs
    USE_SSL = False  # Railway's proxy hanterar SSL
    # Frontend ska använda WSS automatiskt i production
    
    # WebSocket
    WS_PROTOCOL = "wss" if IS_PRODUCTION else "ws"
    WS_HEARTBEAT_INTERVAL = int(os.getenv("WS_HEARTBEAT_INTERVAL", 30))
    
    # CORS
    if IS_PRODUCTION:
        ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")
    else:
        ALLOWED_ORIGINS = ["*"]  # Allow all in development
    
    # Security
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "your-secret-key-here-generate-new-one")
    JWT_SECRET = os.getenv("JWT_SECRET", "your-jwt-secret-here-change-me")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", 24))
    SESSION_API_TOKEN = os.getenv("SESSION_API_TOKEN", "super-secret-token-change-me")
    
    # Message settings
    BASE_DELETE_TIME_SECONDS = int(os.getenv("BASE_DELETE_TIME_SECONDS", 30))
    TIME_PER_CHARACTER_SECONDS = float(os.getenv("TIME_PER_CHARACTER_SECONDS", 0.5))
    MAX_MESSAGE_LIFETIME_SECONDS = int(os.getenv("MAX_MESSAGE_LIFETIME_SECONDS", 300))
    CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", 5))
    INACTIVITY_TIMEOUT_SECONDS = int(os.getenv("INACTIVITY_TIMEOUT_SECONDS", 30))
    
    # Daily cleanup (clear data files)
    DAILY_CLEANUP_HOUR = int(os.getenv("DAILY_CLEANUP_HOUR", 5))  # 05:00
    DAILY_CLEANUP_MINUTE = int(os.getenv("DAILY_CLEANUP_MINUTE", 0))
    
    # Database
    DB_PATH = os.getenv("DB_PATH", "data/chat.db")
    
    # File paths
    DATA_DIR = "data"
    SESSIONS_FILE = f"{DATA_DIR}/sessions.json"
    TRUSTED_FILE = f"{DATA_DIR}/trusted_devices.json"
    ONBOARDING_FILE = f"{DATA_DIR}/onboarding.json"
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        errors = []
        
        if cls.IS_PRODUCTION:
            if cls.ENCRYPTION_KEY == "your-secret-key-here-generate-new-one":
                errors.append("ENCRYPTION_KEY must be set in production")
            if cls.JWT_SECRET == "your-jwt-secret-here-change-me":
                errors.append("JWT_SECRET must be set in production")
            if cls.SESSION_API_TOKEN == "super-secret-token-change-me":
                errors.append("SESSION_API_TOKEN must be set in production")
            # Railway/Cloudflare hanterar SSL - inga cert-filer behövs
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
        
        return True
    
    @classmethod
    def print_config(cls):
        """Print current configuration"""
        print("=" * 60)
        print(f"🔧 CONFIGURATION")
        print("=" * 60)
        print(f"Environment:     {cls.ENVIRONMENT.value}")
        print(f"Host:            {cls.HOST}:{cls.PORT}")
        print(f"SSL Proxy:       Railway/Cloudflare handles SSL")
        print(f"WS Protocol:     {cls.WS_PROTOCOL}://")
        print(f"CORS Origins:    {cls.ALLOWED_ORIGINS}")
        print(f"Daily Cleanup:   {cls.DAILY_CLEANUP_HOUR:02d}:{cls.DAILY_CLEANUP_MINUTE:02d}")
        print("=" * 60)

config = Config()