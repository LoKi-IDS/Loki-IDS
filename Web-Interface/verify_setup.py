#!/usr/bin/env python3
"""
Quick verification script to check if the web interface is set up correctly.
"""
import sys
import os

def check_dependencies():
    """Check if all required packages are installed."""
    print("[*] Checking dependencies...")
    required = [
        'fastapi',
        'uvicorn',
        'sqlalchemy',
        'aiosqlite',
        'pydantic',
        'websockets',
        'yaml',
        'psutil'
    ]
    
    missing = []
    for package in required:
        try:
            if package == 'yaml':
                __import__('yaml')
            elif package == 'psutil':
                __import__('psutil')
            else:
                __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} (missing)")
            missing.append(package)
    
    if missing:
        print(f"\n[!] Missing packages: {', '.join(missing)}")
        print("[*] Install with: pip install -r requirements.txt")
        return False
    return True


def check_structure():
    """Check if all required files and directories exist."""
    print("\n[*] Checking project structure...")
    
    required_paths = [
        'api/main.py',
        'api/models/database.py',
        'api/routes/alerts.py',
        'api/routes/signatures.py',
        'api/routes/blacklist.py',
        'api/routes/stats.py',
        'api/routes/system.py',
        'api/routes/websocket.py',
        'integration/db_logger.py',
        'integration/blacklist_manager.py',
        'integration/ids_integration.py',
        'static/index.html',
        'static/css/style.css',
        'static/js/app.js',
        'requirements.txt'
    ]
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    missing = []
    
    for path in required_paths:
        full_path = os.path.join(base_dir, path)
        if os.path.exists(full_path):
            print(f"  ✓ {path}")
        else:
            print(f"  ✗ {path} (missing)")
            missing.append(path)
    
    if missing:
        print(f"\n[!] Missing files: {len(missing)}")
        return False
    return True


def check_database():
    """Check if database can be initialized."""
    print("\n[*] Checking database setup...")
    
    try:
        import asyncio
        from api.models.database import init_db
        
        async def test_db():
            await init_db()
            print("  ✓ Database can be initialized")
            return True
        
        result = asyncio.run(test_db())
        return result
    except Exception as e:
        print(f"  ✗ Database initialization failed: {e}")
        return False


def main():
    print("=" * 60)
    print("  Loki IDS Web Interface - Setup Verification")
    print("=" * 60)
    
    all_ok = True
    
    # Check dependencies
    if not check_dependencies():
        all_ok = False
    
    # Check structure
    if not check_structure():
        all_ok = False
    
    # Check database
    if not check_database():
        all_ok = False
    
    print("\n" + "=" * 60)
    if all_ok:
        print("  ✓ All checks passed! Setup looks good.")
        print("\n[*] Next steps:")
        print("  1. Start the web interface: ./start_web_server.sh")
        print("  2. Access dashboard: http://localhost:8080")
        print("  3. See INTEGRATION.md for deployment instructions")
    else:
        print("  ✗ Some checks failed. Please fix the issues above.")
        sys.exit(1)
    print("=" * 60)


if __name__ == "__main__":
    main()


