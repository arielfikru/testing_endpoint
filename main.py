import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

app = FastAPI(
    title="Anime Website API",
    description="Backend API for Anime Streaming Website",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Konfigurasi Database
MONGODB_URL = os.getenv("MONGODB_URL")
if not MONGODB_URL:
    raise ValueError("MONGODB_URL environment variable is not set")

client = AsyncIOMotorClient(MONGODB_URL)
db = client.anime_db

# Konfigurasi Security
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class User(BaseModel):
    id: str
    username: str
    email: str

class PostCreate(BaseModel):
    title: str
    embed_url: str
    description: Optional[str] = None

class Post(BaseModel):
    id: str
    title: str
    embed_url: str
    description: Optional[str] = None
    user_id: str
    created_at: datetime

# Security functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return User(id=str(user["_id"]), username=user["username"], email=user["email"])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.get("/")
async def root():
    return {
        "message": "Welcome to Anime Website API",
        "version": "1.0.0",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow()
    }

# Routes
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    # Check if username or email already exists
    if await db.users.find_one({"$or": [{"username": user.username}, {"email": user.email}]}):
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash password and create user
    hashed_password = pwd_context.hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    user_dict["created_at"] = datetime.utcnow()
    
    result = await db.users.insert_one(user_dict)
    
    return User(
        id=str(result.inserted_id),
        username=user.username,
        email=user.email
    )

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/posts", response_model=Post)
async def create_post(post: PostCreate, current_user: User = Depends(get_current_user)):
    post_dict = post.dict()
    post_dict.update({
        "user_id": current_user.id,
        "created_at": datetime.utcnow()
    })
    
    result = await db.posts.insert_one(post_dict)
    
    created_post = await db.posts.find_one({"_id": result.inserted_id})
    return Post(
        id=str(created_post["_id"]),
        title=created_post["title"],
        embed_url=created_post["embed_url"],
        description=created_post.get("description"),
        user_id=str(created_post["user_id"]),
        created_at=created_post["created_at"]
    )

@app.get("/posts", response_model=List[Post])
async def get_posts(skip: int = 0, limit: int = 10):
    posts = await db.posts.find().skip(skip).limit(limit).to_list(length=limit)
    return [
        Post(
            id=str(post["_id"]),
            title=post["title"],
            embed_url=post["embed_url"],
            description=post.get("description"),
            user_id=str(post["user_id"]),
            created_at=post["created_at"]
        ) for post in posts
    ]

# Untuk deployment di Vercel
def create_app():
    return app