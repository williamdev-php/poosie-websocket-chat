import os
import asyncio
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from config import config

class CleanupScheduler:
    """
    Schemaläggare för daglig städning av datafiler.
    Kör automatiskt kl 05:00 varje dag.
    """
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.is_running = False
        print("🧹 CleanupScheduler initierad")
    
    async def daily_cleanup(self):
        """Huvudsaklig cleanup-funktion som körs dagligen"""
        print(f"\n{'='*60}")
        print(f"🧹 DAGLIG STÄDNING STARTAD - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        try:
            # 1. Rensa JSON-filer i data/
            await self._cleanup_json_files()
            
            # 2. Rensa gammal last_seen data (äldre än 30 dagar)
            await self._cleanup_last_seen()
            
            # 3. Optimera databas
            await self._vacuum_database()
            
            print(f"{'='*60}")
            print(f"✅ DAGLIG STÄDNING KLAR")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"❌ Fel vid daglig städning: {e}")
    
    async def _cleanup_json_files(self):
        """Rensa alla JSON-filer i data/-katalogen"""
        files_to_clean = [
            config.SESSIONS_FILE,
            config.TRUSTED_FILE,
            config.ONBOARDING_FILE,
            "data/login_control.json"  # 🆕 Lägg till login control fil (OBS: RENSA INTE DENNA!)
        ]
        
        cleaned_count = 0
        for filepath in files_to_clean:
            # 🆕 SKIPPA login_control.json - vi vill behålla den!
            if "login_control" in filepath:
                print(f"   ⏭️ Behåller: {filepath} (login control)")
                continue
            
            if os.path.exists(filepath):
                try:
                    # Rensa innehållet (skriv tom lista/dict beroende på fil)
                    if "sessions" in filepath:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write('[]')  # Tom array
                    else:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write('{}')  # Tomt objekt
                    
                    cleaned_count += 1
                    print(f"   ✓ Rensade: {filepath}")
                except Exception as e:
                    print(f"   ✗ Kunde inte rensa {filepath}: {e}")
        
        print(f"📁 Rensade {cleaned_count} JSON-filer")
    
    async def _cleanup_last_seen(self):
        """Rensa gammal last_seen data"""
        try:
            from last_seen_store import last_seen_store
            deleted = last_seen_store.clear_old_data(days_old=30)
            print(f"📊 Rensade {deleted} gamla last_seen poster")
        except Exception as e:
            print(f"❌ Kunde inte rensa last_seen: {e}")
    
    async def _vacuum_database(self):
        """Optimera SQLite-databasen"""
        try:
            from last_seen_store import last_seen_store
            last_seen_store.vacuum()
            print(f"💾 Databas optimerad")
        except Exception as e:
            print(f"❌ Kunde inte optimera databas: {e}")
    
    def start(self):
        """Starta schemaläggaren"""
        if self.is_running:
            print("⚠️ Cleanup scheduler redan igång")
            return
        
        # Schemalägg daglig cleanup kl 05:00
        self.scheduler.add_job(
            self.daily_cleanup,
            trigger=CronTrigger(
                hour=config.DAILY_CLEANUP_HOUR,
                minute=config.DAILY_CLEANUP_MINUTE
            ),
            id='daily_cleanup',
            name='Daglig städning av datafiler',
            replace_existing=True
        )
        
        self.scheduler.start()
        self.is_running = True
        
        next_run = self.scheduler.get_job('daily_cleanup').next_run_time
        print(f"⏰ Daglig städning schemalagd: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def stop(self):
        """Stoppa schemaläggaren"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            self.is_running = False
            print("🛑 Cleanup scheduler stoppad")
    
    async def run_manual_cleanup(self):
        """Kör cleanup manuellt (för testning)"""
        print("🔧 Kör manuell cleanup...")
        await self.daily_cleanup()

# Singleton
cleanup_scheduler = CleanupScheduler()