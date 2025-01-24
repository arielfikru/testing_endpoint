from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import os
from uuid import uuid4
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(title="Anime Website API")

# Konfigurasi Security
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in .env file")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JSON Storage
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
POSTS_FILE = os.path.join(DATA_DIR, "posts.json")

# Membuat direktori data jika belum ada
os.makedirs(DATA_DIR, exist_ok=True)

# Inisialisasi file JSON jika belum ada
def init_json_files():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump([], f)
    if not os.path.exists(POSTS_FILE):
        with open(POSTS_FILE, 'w') as f:
            json.dump([], f)

init_json_files()

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

# JSON Storage Functions
def read_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def write_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, indent=2, default=str)

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
        
        users = read_json(USERS_FILE)
        user = next((u for u in users if u["id"] == user_id), None)
        
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return User(id=user["id"], username=user["username"], email=user["email"])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# Routes
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    users = read_json(USERS_FILE)
    
    # Check if username or email already exists
    if any(u["username"] == user.username or u["email"] == user.email for u in users):
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user
    user_dict = {
        "id": str(uuid4()),
        "username": user.username,
        "email": user.email,
        "password": pwd_context.hash(user.password)
    }
    
    users.append(user_dict)
    write_json(USERS_FILE, users)
    
    return User(
        id=user_dict["id"],
        username=user_dict["username"],
        email=user_dict["email"]
    )

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = read_json(USERS_FILE)
    user = next((u for u in users if u["username"] == form_data.username), None)
    
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user["id"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/posts", response_model=Post)
async def create_post(post: PostCreate, current_user: User = Depends(get_current_user)):
    posts = read_json(POSTS_FILE)
    
    post_dict = {
        "id": str(uuid4()),
        "title": post.title,
        "embed_url": post.embed_url,
        "description": post.description,
        "user_id": current_user.id,
        "created_at": str(datetime.utcnow())
    }
    
    posts.append(post_dict)
    write_json(POSTS_FILE, posts)
    
    return Post(
        id=post_dict["id"],
        title=post_dict["title"],
        embed_url=post_dict["embed_url"],
        description=post_dict["description"],
        user_id=post_dict["user_id"],
        created_at=datetime.fromisoformat(post_dict["created_at"].replace('Z', '+00:00'))
    )

@app.get("/posts", response_model=List[Post])
async def get_posts(skip: int = 0, limit: int = 10):
    posts = read_json(POSTS_FILE)
    
    # Simple pagination
    paginated_posts = posts[skip:skip + limit]
    
    return [
        Post(
            id=post["id"],
            title=post["title"],
            embed_url=post["embed_url"],
            description=post["description"],
            user_id=post["user_id"],
            created_at=datetime.fromisoformat(post["created_at"].replace('Z', '+00:00'))
        ) for post in paginated_posts
    ]

# Untuk deployment di Vercel
def create_app():
    return app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)