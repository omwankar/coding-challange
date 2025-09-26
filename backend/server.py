from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import secrets
from enum import Enum

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Create the main app without a prefix
app = FastAPI(title="Store Rating System", description="A comprehensive store rating platform")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Enums
class UserRole(str, Enum):
    SYSTEM_ADMIN = "system_admin"
    NORMAL_USER = "normal_user" 
    STORE_OWNER = "store_owner"

class StoreStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

# Pydantic Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=20, max_length=60)
    email: EmailStr
    address: str = Field(..., max_length=400)
    role: UserRole
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

class UserCreate(BaseModel):
    name: str = Field(..., min_length=20, max_length=60)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=16)
    address: str = Field(..., max_length=400)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class PasswordUpdate(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=16)

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=16)

class Store(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    address: str = Field(..., max_length=400)
    owner_id: str
    status: StoreStatus = StoreStatus.PENDING
    average_rating: float = 0.0
    total_ratings: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StoreCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    address: str = Field(..., max_length=400)

class StoreOwnerRegistration(BaseModel):
    user: UserCreate
    store: StoreCreate

class Rating(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    store_id: str
    rating: int = Field(..., ge=1, le=5)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RatingSubmit(BaseModel):
    store_id: str
    rating: int = Field(..., ge=1, le=5)

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class DashboardStats(BaseModel):
    total_users: int
    total_stores: int
    total_ratings: int

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def validate_password_strength(password: str) -> bool:
    """Validate password: 8-16 chars, at least one uppercase and one special char"""
    if len(password) < 8 or len(password) > 16:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    return has_upper and has_special

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    payload = verify_token(token)
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_data = await db.users.find_one({"id": user_id})
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    return User(**user_data)

def require_role(allowed_roles: List[UserRole]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

async def send_reset_email(email: str, token: str):
    """Send password reset email (mock implementation)"""
    # In production, implement actual email sending
    print(f"Password reset email sent to {email} with token: {token}")

async def calculate_store_rating(store_id: str):
    """Calculate and update store's average rating"""
    pipeline = [
        {"$match": {"store_id": store_id}},
        {"$group": {
            "_id": "$store_id",
            "average_rating": {"$avg": "$rating"},
            "total_ratings": {"$sum": 1}
        }}
    ]
    
    result = await db.ratings.aggregate(pipeline).to_list(1)
    if result:
        avg_rating = round(result[0]["average_rating"], 2)
        total_ratings = result[0]["total_ratings"]
    else:
        avg_rating = 0.0
        total_ratings = 0
    
    await db.stores.update_one(
        {"id": store_id},
        {"$set": {"average_rating": avg_rating, "total_ratings": total_ratings}}
    )
    
    return avg_rating, total_ratings

# Initialize Admin User
async def init_admin_user():
    admin_exists = await db.users.find_one({"role": UserRole.SYSTEM_ADMIN})
    if not admin_exists:
        admin_user = User(
            name="System Administrator Account",
            email="admin@storerate.com",
            address="System Administrator Address - Default Location",
            role=UserRole.SYSTEM_ADMIN
        )
        
        hashed_password = hash_password("AdminPass123!")
        user_dict = admin_user.dict()
        user_dict["password"] = hashed_password
        
        await db.users.insert_one(user_dict)
        print("Admin user created: admin@storerate.com / AdminPass123!")

# Authentication Routes
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Validate password strength
    if not validate_password_strength(user_data.password):
        raise HTTPException(
            status_code=400, 
            detail="Password must be 8-16 characters with at least one uppercase letter and one special character"
        )
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        name=user_data.name,
        email=user_data.email,
        address=user_data.address,
        role=UserRole.NORMAL_USER
    )
    
    hashed_password = hash_password(user_data.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    
    await db.users.insert_one(user_dict)
    
    # Create token
    token = create_access_token({"sub": user.id, "role": user.role.value})
    
    return Token(access_token=token, token_type="bearer", user=user)

@api_router.post("/auth/login", response_model=Token)
async def login(login_data: UserLogin):
    user_data = await db.users.find_one({"email": login_data.email})
    if not user_data or not verify_password(login_data.password, user_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = User(**user_data)
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is inactive")
    
    token = create_access_token({"sub": user.id, "role": user.role.value})
    
    return Token(access_token=token, token_type="bearer", user=user)

@api_router.post("/auth/store-owner-register")
async def register_store_owner(registration_data: StoreOwnerRegistration):
    # Validate password strength
    if not validate_password_strength(registration_data.user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8-16 characters with at least one uppercase letter and one special character"
        )
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": registration_data.user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create store owner user
    user = User(
        name=registration_data.user.name,
        email=registration_data.user.email,
        address=registration_data.user.address,
        role=UserRole.STORE_OWNER
    )
    
    hashed_password = hash_password(registration_data.user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    
    await db.users.insert_one(user_dict)
    
    # Create store with pending status
    store = Store(
        name=registration_data.store.name,
        email=registration_data.store.email,
        address=registration_data.store.address,
        owner_id=user.id,
        status=StoreStatus.PENDING
    )
    
    await db.stores.insert_one(store.dict())
    
    return {"message": "Store owner registration submitted for admin approval", "user_id": user.id, "store_id": store.id}

@api_router.put("/auth/update-password")
async def update_password(password_data: PasswordUpdate, current_user: User = Depends(get_current_user)):
    # Verify current password
    user_data = await db.users.find_one({"id": current_user.id})
    if not verify_password(password_data.current_password, user_data["password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password strength
    if not validate_password_strength(password_data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8-16 characters with at least one uppercase letter and one special character"
        )
    
    # Update password
    hashed_password = hash_password(password_data.new_password)
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"password": hashed_password}}
    )
    
    return {"message": "Password updated successfully"}

@api_router.post("/auth/password-reset-request")
async def request_password_reset(reset_request: PasswordResetRequest):
    user_data = await db.users.find_one({"email": reset_request.email})
    if not user_data:
        # Return success even if user doesn't exist (security best practice)
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    # Store reset token in database
    await db.password_resets.insert_one({
        "user_id": user_data["id"],
        "token": reset_token,
        "expires_at": expires_at,
        "used": False
    })
    
    # Send email (mock implementation)
    await send_reset_email(reset_request.email, reset_token)
    
    return {"message": "If the email exists, a password reset link has been sent"}

@api_router.post("/auth/password-reset")
async def reset_password(reset_data: PasswordReset):
    # Validate new password strength
    if not validate_password_strength(reset_data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8-16 characters with at least one uppercase letter and one special character"
        )
    
    # Find and validate reset token
    reset_record = await db.password_resets.find_one({
        "token": reset_data.token,
        "used": False,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    
    if not reset_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Update password
    hashed_password = hash_password(reset_data.new_password)
    await db.users.update_one(
        {"id": reset_record["user_id"]},
        {"$set": {"password": hashed_password}}
    )
    
    # Mark token as used
    await db.password_resets.update_one(
        {"token": reset_data.token},
        {"$set": {"used": True}}
    )
    
    return {"message": "Password reset successfully"}

# Admin Routes
@api_router.get("/admin/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))):
    total_users = await db.users.count_documents({})
    total_stores = await db.stores.count_documents({})
    total_ratings = await db.ratings.count_documents({})
    
    return DashboardStats(
        total_users=total_users,
        total_stores=total_stores, 
        total_ratings=total_ratings
    )

@api_router.post("/admin/users", response_model=User)
async def create_user_by_admin(user_data: UserCreate, role: UserRole, current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))):
    # Validate password strength
    if not validate_password_strength(user_data.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8-16 characters with at least one uppercase letter and one special character"
        )
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user with specified role
    user = User(
        name=user_data.name,
        email=user_data.email,
        address=user_data.address,
        role=role
    )
    
    hashed_password = hash_password(user_data.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    
    await db.users.insert_one(user_dict)
    
    return user

@api_router.get("/admin/users", response_model=List[User])
async def get_all_users(
    name: Optional[str] = None,
    email: Optional[str] = None, 
    address: Optional[str] = None,
    role: Optional[UserRole] = None,
    current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))
):
    query = {}
    if name:
        query["name"] = {"$regex": name, "$options": "i"}
    if email:
        query["email"] = {"$regex": email, "$options": "i"}
    if address:
        query["address"] = {"$regex": address, "$options": "i"}
    if role:
        query["role"] = role.value
    
    users = await db.users.find(query, {"password": 0}).to_list(1000)
    return [User(**user) for user in users]

@api_router.get("/admin/stores", response_model=List[Store])
async def get_all_stores(
    name: Optional[str] = None,
    email: Optional[str] = None,
    address: Optional[str] = None,
    current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))
):
    query = {}
    if name:
        query["name"] = {"$regex": name, "$options": "i"}
    if email:
        query["email"] = {"$regex": email, "$options": "i"}  
    if address:
        query["address"] = {"$regex": address, "$options": "i"}
    
    stores = await db.stores.find(query).to_list(1000)
    return [Store(**store) for store in stores]

@api_router.put("/admin/stores/{store_id}/approve")
async def approve_store(store_id: str, current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))):
    result = await db.stores.update_one(
        {"id": store_id},
        {"$set": {"status": StoreStatus.APPROVED}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Store not found")
    
    return {"message": "Store approved successfully"}

@api_router.put("/admin/stores/{store_id}/reject")
async def reject_store(store_id: str, current_user: User = Depends(require_role([UserRole.SYSTEM_ADMIN]))):
    result = await db.stores.update_one(
        {"id": store_id},
        {"$set": {"status": StoreStatus.REJECTED}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Store not found")
    
    return {"message": "Store rejected"}

# Store Routes
@api_router.get("/stores", response_model=List[Store])
async def get_stores(
    name: Optional[str] = None,
    address: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = {"status": StoreStatus.APPROVED}
    if name:
        query["name"] = {"$regex": name, "$options": "i"}
    if address:
        query["address"] = {"$regex": address, "$options": "i"}
    
    stores = await db.stores.find(query).to_list(1000)
    return [Store(**store) for store in stores]

@api_router.get("/stores/{store_id}", response_model=Store)
async def get_store(store_id: str, current_user: User = Depends(get_current_user)):
    store_data = await db.stores.find_one({"id": store_id})
    if not store_data:
        raise HTTPException(status_code=404, detail="Store not found")
    
    return Store(**store_data)

# Rating Routes
@api_router.post("/ratings")
async def submit_rating(rating_data: RatingSubmit, current_user: User = Depends(get_current_user)):
    # Verify store exists and is approved
    store_data = await db.stores.find_one({"id": rating_data.store_id, "status": StoreStatus.APPROVED})
    if not store_data:
        raise HTTPException(status_code=404, detail="Store not found or not approved")
    
    # Check if user already rated this store
    existing_rating = await db.ratings.find_one({
        "user_id": current_user.id,
        "store_id": rating_data.store_id
    })
    
    rating_obj = Rating(
        user_id=current_user.id,
        store_id=rating_data.store_id,
        rating=rating_data.rating
    )
    
    if existing_rating:
        # Update existing rating
        rating_obj.updated_at = datetime.now(timezone.utc)
        await db.ratings.update_one(
            {"user_id": current_user.id, "store_id": rating_data.store_id},
            {"$set": {"rating": rating_data.rating, "updated_at": rating_obj.updated_at}}
        )
    else:
        # Create new rating
        await db.ratings.insert_one(rating_obj.dict())
    
    # Recalculate store's average rating
    await calculate_store_rating(rating_data.store_id)
    
    return {"message": "Rating submitted successfully"}

@api_router.get("/ratings/my-rating/{store_id}")
async def get_my_rating(store_id: str, current_user: User = Depends(get_current_user)):
    rating_data = await db.ratings.find_one({
        "user_id": current_user.id,
        "store_id": store_id
    })
    
    if not rating_data:
        return {"rating": None}
    
    return {"rating": rating_data["rating"]}

# Store Owner Routes
@api_router.get("/store-owner/dashboard")
async def get_store_owner_dashboard(current_user: User = Depends(require_role([UserRole.STORE_OWNER]))):
    # Get owner's store
    store_data = await db.stores.find_one({"owner_id": current_user.id})
    if not store_data:
        raise HTTPException(status_code=404, detail="Store not found")
    
    store = Store(**store_data)
    
    # Get users who rated this store
    ratings = await db.ratings.find({"store_id": store.id}).to_list(1000)
    user_ids = [rating["user_id"] for rating in ratings]
    
    users_who_rated = []
    if user_ids:
        users_data = await db.users.find(
            {"id": {"$in": user_ids}},
            {"password": 0}
        ).to_list(1000)
        users_who_rated = [User(**user) for user in users_data]
    
    return {
        "store": store,
        "users_who_rated": users_who_rated,
        "average_rating": store.average_rating,
        "total_ratings": store.total_ratings
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    await init_admin_user()
    logger.info("Application started successfully")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()