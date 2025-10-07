import os
import sys
from pathlib import Path
from dotenv import load_dotenv

print("=== Environment Debugging ===\n")

# 1. Print current working directory
print(f"Current working directory: {os.getcwd()}")

# 2. Check if .env file exists
env_path = Path('.env')
print(f"Looking for .env file at: {env_path.absolute()}")
print(f"File exists: {env_path.exists()}")

# 3. Load .env file
load_dotenv(override=True)  # Force reload
print("\nLoaded environment variables:")

# 4. Print all environment variables (be careful with sensitive data)
print("\nEnvironment variables:")
for key, value in os.environ.items():
    if any(k.lower() in key.lower() for k in ['key', 'token', 'secret', 'password']):
        masked = f"{value[:4]}...{value[-2:] if len(value) > 6 else '***'}" if value else "[empty]"
        print(f"{key}: {masked}")
    else:
        print(f"{key}: {value}")

# 5. Check specific API keys
print("\nChecking API keys:")
api_keys = {
    'ETHERSCAN_API_KEY': 32,
    'POLYGONSCAN_API_KEY': 32,
    'ARBISCAN_API_KEY': 32,
    'OPTIMISM_ETHERSCAN_API_KEY': 32
}

all_valid = True
for key, min_length in api_keys.items():
    value = os.getenv(key, '').strip()
    if not value:
        print(f"❌ {key}: Not found in environment")
        all_valid = False
    elif len(value) < min_length:
        print(f"⚠️  {key}: Too short (expected at least {min_length} chars, got {len(value)})")
        all_valid = False
    else:
        print(f"✅ {key}: Found and valid length ({len(value)} chars)")

print("\n=== Debug Complete ===")
if all_valid:
    print("✅ All API keys appear to be valid")
else:
    print("❌ Some API keys are missing or invalid")
