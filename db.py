"""
ThreatPulse Database Integration Module (MongoDB)
Handles MongoDB connection, user account persistence, secure authentication,
password hashing with PBKDF2-HMAC-SHA256, and user profile management.
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Logger setup
logger = logging.getLogger("threatpulse.db")

# Default MongoDB configuration
DEFAULT_MONGO_URI = "mongodb://localhost:27017/"
DEFAULT_DB_NAME = "threatpulse"

_client = None
_db = None
_initialized = False


def get_mongo_uri() -> str:
    """Returns the MongoDB connection URI from environment or default."""
    return os.getenv("MONGO_URI") or os.getenv("MONGODB_URI") or DEFAULT_MONGO_URI


def get_mongo_db_name() -> str:
    """Returns the MongoDB database name from environment or default."""
    return os.getenv("MONGO_DB_NAME") or DEFAULT_DB_NAME


def get_mongo_client():
    """Returns a singleton MongoDB client with connection pooling and fast failover."""
    global _client
    if _client is None:
        try:
            import pymongo
            uri = get_mongo_uri()
            # serverSelectionTimeoutMS=2000 ensures fast feedback if server is unreachable
            _client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=2500, connect=False)
        except Exception as e:
            logger.error(f"Failed to create MongoClient: {e}")
            return None
    return _client


def get_db():
    """Returns the MongoDB database instance, initializing indexes if needed."""
    global _db, _initialized
    if _db is None:
        client = get_mongo_client()
        if client is not None:
            db_name = get_mongo_db_name()
            _db = client[db_name]
            
            if not _initialized:
                try:
                    # Create unique index on email for the users collection
                    _db.users.create_index("email", unique=True)
                    _db.users.create_index("created_at")
                    _initialized = True
                except Exception as e:
                    logger.warning(f"Index creation warning: {e}")
    return _db


def check_db_connection() -> Tuple[bool, str]:
    """
    Checks whether MongoDB is alive and reachable.
    Returns (True, "MongoDB vX.X Connected") or (False, "Error message").
    """
    try:
        import pymongo
        client = get_mongo_client()
        if client is None:
            return False, "PyMongo client could not be instantiated."
        
        # Test connection with a quick ping
        client.admin.command('ping')
        info = client.server_info()
        version = info.get("version", "unknown")
        db_name = get_mongo_db_name()
        return True, f"MongoDB v{version} Connected ({db_name})"
    except Exception as e:
        return False, f"MongoDB connection error: {str(e)}"


# ─────────────────────────────────────────────────────────────────────────────
# SECURE PASSWORD HASHING (PBKDF2-HMAC-SHA256 with 16-byte cryptographically secure salt)
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hashes a password with a unique salt using 100,000 iterations of PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return f"{salt.hex()}${pwd_hash.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a plain text password against a stored salt$hash string using constant-time comparison."""
    try:
        if not stored_hash or "$" not in stored_hash:
            return False
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
        return hmac.compare_digest(expected_hash.hex(), hash_hex)
    except Exception as e:
        logger.error(f"Error during password verification: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# USER ACCOUNT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_user(user_doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Strips internal sensitive fields (like password_hash) from user document for safe UI consumption."""
    if not user_doc:
        return None
    safe = dict(user_doc)
    safe.pop("password_hash", None)
    if "_id" in safe:
        safe["_id"] = str(safe["_id"])
    if isinstance(safe.get("created_at"), datetime):
        safe["created_at_str"] = safe["created_at"].strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(safe.get("last_login"), datetime):
        safe["last_login_str"] = safe["last_login"].strftime("%Y-%m-%d %H:%M:%S UTC")
    return safe


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Fetches a user by email address (case-insensitive)."""
    db = get_db()
    if db is None:
        return None
    try:
        user = db.users.find_one({"email": email.strip().lower()})
        return user
    except Exception as e:
        logger.error(f"Error fetching user by email: {e}")
        return None


def create_user(
    name: str,
    email: str,
    password: str,
    role: str = "Security Analyst",
    org: str = "ThreatPulse Defense"
) -> Dict[str, Any]:
    """
    Registers and persists a new user account in MongoDB.
    Returns {"success": True, "user": safe_user_dict} or {"success": False, "error": str}.
    """
    name_clean = name.strip()
    email_clean = email.strip().lower()
    
    if not name_clean:
        return {"success": False, "error": "Full Name is required."}
    if not email_clean or "@" not in email_clean or "." not in email_clean:
        return {"success": False, "error": "A valid email address is required."}
    if not password or len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters long."}
    
    db = get_db()
    if db is None:
        return {"success": False, "error": "Database service is currently unreachable. Please ensure MongoDB is running."}
    
    try:
        # Check if email is already registered
        existing = db.users.find_one({"email": email_clean})
        if existing:
            return {"success": False, "error": f"An account with email '{email_clean}' already exists. Please sign in."}
        
        # Hash password and construct document
        now = datetime.now(timezone.utc)
        user_doc = {
            "name": name_clean,
            "email": email_clean,
            "password_hash": hash_password(password),
            "role": role.strip() if role else "Security Analyst",
            "org": org.strip() if org else "ThreatPulse Defense",
            "auth_provider": "local",
            "created_at": now,
            "last_login": now,
            "login_count": 1,
            "is_active": True
        }
        
        result = db.users.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        
        logger.info(f"Successfully registered user: {email_clean}")
        return {"success": True, "user": sanitize_user(user_doc)}
        
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return {"success": False, "error": f"Registration failed: {str(e)}"}


def authenticate_user(email: str, password: str) -> Dict[str, Any]:
    """
    Authenticates a user against MongoDB records.
    Returns {"success": True, "user": safe_user_dict} or {"success": False, "error": str}.
    """
    email_clean = email.strip().lower()
    
    if not email_clean or not password:
        return {"success": False, "error": "Please provide both email and password."}
        
    db = get_db()
    if db is None:
        return {"success": False, "error": "Database service is unreachable. Check your MongoDB connection."}
        
    try:
        user = db.users.find_one({"email": email_clean})
        if not user:
            return {"success": False, "error": "No account found with this email. Please check your credentials or register."}
            
        stored_hash = user.get("password_hash")
        if not stored_hash or not verify_password(password, stored_hash):
            return {"success": False, "error": "Incorrect password. Please try again."}
            
        # Update last_login timestamp and login count
        now = datetime.now(timezone.utc)
        db.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"last_login": now},
                "$inc": {"login_count": 1}
            }
        )
        user["last_login"] = now
        user["login_count"] = user.get("login_count", 0) + 1
        
        logger.info(f"User authenticated successfully: {email_clean}")
        return {"success": True, "user": sanitize_user(user)}
        
    except Exception as e:
        logger.error(f"Error authenticating user: {e}")
        return {"success": False, "error": f"Authentication failed: {str(e)}"}


def upsert_oauth_user(
    name: str,
    email: str,
    role: str = "Security Analyst",
    org: str = "ThreatPulse Defense",
    provider: str = "google"
) -> Dict[str, Any]:
    """
    Handles social/OAuth accounts (Google, GitHub), creating them in MongoDB if they don't exist,
    or updating their last login if they do.
    """
    email_clean = email.strip().lower()
    db = get_db()
    if db is None:
        # Fallback to local session if DB is offline
        return {
            "success": True,
            "user": {
                "name": name,
                "email": email_clean,
                "role": role,
                "org": org,
                "auth_provider": provider
            }
        }
        
    try:
        now = datetime.now(timezone.utc)
        user = db.users.find_one({"email": email_clean})
        
        if user:
            db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {"last_login": now, "auth_provider": provider},
                    "$inc": {"login_count": 1}
                }
            )
            user["last_login"] = now
            user["login_count"] = user.get("login_count", 0) + 1
            return {"success": True, "user": sanitize_user(user)}
        else:
            new_user = {
                "name": name.strip(),
                "email": email_clean,
                "password_hash": None,
                "role": role,
                "org": org,
                "auth_provider": provider,
                "created_at": now,
                "last_login": now,
                "login_count": 1,
                "is_active": True
            }
            res = db.users.insert_one(new_user)
            new_user["_id"] = res.inserted_id
            return {"success": True, "user": sanitize_user(new_user)}
            
    except Exception as e:
        logger.error(f"Error in OAuth upsert: {e}")
        return {
            "success": True,
            "user": {
                "name": name,
                "email": email_clean,
                "role": role,
                "org": org,
                "auth_provider": provider
            }
        }


def get_user_count() -> int:
    """Returns total registered users in MongoDB."""
    db = get_db()
    if db is not None:
        try:
            return db.users.count_documents({})
        except Exception:
            return 0
    return 0


def reset_password(email: str, new_password: str) -> Dict[str, Any]:
    """Resets the password for a registered user in MongoDB."""
    email_clean = email.strip().lower()
    if not email_clean:
        return {"success": False, "error": "Please provide an email address."}
    if not new_password or len(new_password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters long."}
        
    db = get_db()
    if db is None:
        return {"success": False, "error": "Database service is unreachable."}
        
    try:
        user = db.users.find_one({"email": email_clean})
        if not user:
            return {"success": False, "error": f"No account found with email '{email_clean}'."}
            
        new_hash = hash_password(new_password)
        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": new_hash, "updated_at": datetime.now(timezone.utc)}}
        )
        logger.info(f"Password reset successfully for {email_clean}")
        return {"success": True, "message": "Password successfully updated! Please sign in with your new password."}
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return {"success": False, "error": f"Failed to reset password: {str(e)}"}


def update_user_profile(email: str, name: Optional[str] = None, role: Optional[str] = None, org: Optional[str] = None) -> Dict[str, Any]:
    """Updates profile attributes (name, role, org) for a user in MongoDB."""
    email_clean = email.strip().lower()
    db = get_db()
    if db is None:
        return {"success": False, "error": "Database service is unreachable."}
        
    try:
        user = db.users.find_one({"email": email_clean})
        if not user:
            return {"success": False, "error": "User not found."}
            
        updates = {"updated_at": datetime.now(timezone.utc)}
        if name and name.strip():
            updates["name"] = name.strip()
        if role and role.strip():
            updates["role"] = role.strip()
        if org and org.strip():
            updates["org"] = org.strip()
            
        db.users.update_one({"_id": user["_id"]}, {"$set": updates})
        updated_user = db.users.find_one({"_id": user["_id"]})
        return {"success": True, "user": sanitize_user(updated_user)}
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        return {"success": False, "error": f"Failed to update profile: {str(e)}"}
