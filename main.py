from fastapi import Depends, FastAPI, HTTPException, status, Form, Header, Request, Security
from fastapi.security import HTTPBasicCredentials, HTTPBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from jose.exceptions import JOSEError
from typing_extensions import Annotated
from jsend import jsend
from typing import Union
import secrets
from requests.structures import CaseInsensitiveDict
from pydantic import BaseModel
from fastapi.security.api_key import APIKeyHeader
from attrdict import AttrDict

SECRET_KEY = "ee5eea09ce73da3533f1ad6e8507b1f0f940d11bdb4f166b88daad3b22dfcec9"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30

db = {
    "customer":{
        "customer_xid": "ea0212d3-abd6-406f-8c67-868e814a2436"
    },
    "wallet": {
        "id": "c4d7d61f-b702-44a8-af97-5dbdafa96551",
        "owned_by": "6ef31975-67b0-421a-9493-667569d89556",
        "status": "enabled",
        "enabled_at": "1994-11-05T08:15:30-05:00",
        "balance": 0
    },
    "deposit":{
        "id": "ea0212d3-abd6-406f-8c67-868e814a2433",
        "deposited_by": "526ea8b2-428e-403b-b9fd-f10972e0d6fe",
        "status": "success",
        "deposited_at": "1994-11-05T08:15:30-05:00",
        "amount": 0,
        "reference_id": "f4cee01f-9188-4a29-aa9a-cb7fb97d8e0a"
    },
    "withdrawal":{
        "id": "ea0212d3-abd6-406f-8c67-868e814a2433",
        "withdrawn_by": "526ea8b2-428e-403b-b9fd-f10972e0d6fe",
        "status": "success",
        "withdrawn_at": "1994-11-05T08:15:30-05:00",
        "amount": 260000,
        "reference_id": "c4cee01f-2188-4a29-aa9a-cb7fb97d8e0a"
    },
    "transactions":[
        {
        "id": "7ae5aa7b-821f-4559-874b-07eea5f47962",
        "status": "success",
        "transacted_at": "1994-11-05T08:15:30-05:00",
        "type": "deposit",
        "amount": 14000,
        "reference_id": "305247dc-6081-409c-b418-e9d65dee7a94"
      },
      {
        "id": "7161d0eb-79b9-4177-b454-cad7a53f46dc",
        "status": "failed",
        "transacted_at": "1994-11-10T08:15:30-05:00",
        "type": "withdrawal",
        "amount": 890000,
        "reference_id": "6f07d2db-4db4-4bee-99c8-4db9a430951d"
      },
      {
        "id": "c6dd5b25-d4fe-411c-a9c0-e2a9f1c724b3",
        "status": "success",
        "transacted_at": "1994-11-10T08:15:41-05:00",
        "type": "withdrawal",
        "amount": 890000,
        "reference_id": "57fa2a07-c1b7-40c8-8096-3736d1c8cfde"
      }
    ]
}

class Token(BaseModel):
    token: str 

token_key = APIKeyHeader(name="Authorization")

app = FastAPI()

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

def get_current_token(auth_key: str = Security(token_key)):
    add_parts = ("Token " + auth_key)

    return add_parts

def id_is_unique(collection_name, id_to_check):
    collection = db.get(collection_name, {})
    return id_to_check not in collection

@app.post("/api/v1/init")
async def init_token(customer_xid: Annotated[str, Form()]):
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    access_token = create_access_token(data={"sub": customer_xid}, expires_delta=access_token_expires)
    
    return jsend.success({"token": access_token})

@app.post("/api/v1/wallet")
async def enable_wallet(current_token: Token = Depends(get_current_token)):
    current_status = db.get("wallet", {}).get("status", "")
    wallet_already_enabled = "wallet already enabled"
    if current_status == "disabled":
        update_status = current_status.replace("disabled", "enabled")
        db.setdefault("wallet", {})["status"] = update_status
    else:
        return jsend.fail({"error": "wallet already enabled"})

    return jsend.success({"wallet": db.get("wallet")})

@app.get("/api/v1/wallet")
async def show_wallet_balance(current_token: Token = Depends(get_current_token)):
    current_status = db.get("wallet", {}).get("status", "")
    if current_status == "disabled":
        return jsend.fail({"error": "wallet disabled"})
    else:
        return jsend.success({"wallet": db.get("wallet")})

@app.get("/api/v1/wallet/transactions")
async def show_wallet_transactions(current_token: Token = Depends(get_current_token)):
    current_status = db.get("wallet", {}).get("status", "")
    if current_status == "disabled":
       return jsend.fail({"error": "wallet disabled"})
    else:
       return jsend.success({"transactions": db["transactions"]})

@app.post("/api/v1/wallet/deposits")
async def add_wallet_amount(amount: Annotated[int, Form()], reference_id: Annotated[str, Form()], 
                    current_token: Token = Depends(get_current_token)):

    current_amount = db.get("deposit", {}).get("amount", 0)
    add_amount = current_amount + amount
    reference_id = secrets.token_hex(10)

    check_unique = reference_id
    if id_is_unique("deposit", check_unique):
        db.setdefault("deposit", {})["reference_id"] = check_unique
    else:
        raise HTTPException(status_code=409, detail="Existing Data")

    db.setdefault("deposit", {})["amount"] = add_amount

    return jsend.success({"deposit": db.get("deposit")})

@app.post("/api/v1/wallet/withdrawals")
async def withdrawal_wallet_amount(amount: Annotated[int, Form()], reference_id: Annotated[str, Form()], 
                            current_token: Token = Depends(get_current_token)):
    current_amount = db.get("withdrawal", {}).get("amount", 0)
    if current_amount >= 0:
        withdrawal_amount = current_amount - amount
        db.setdefault("withdrawal", {})["amount"] = withdrawal_amount
    elif current_amount <= 0:
        raise HTTPException(status_code=422, detail="Not Enough Balance")
    else:
        raise HTTPException(status_code=400, detail="Bad Request")
    
    reference_id = secrets.token_hex(10)
    check_unique = reference_id
    if id_is_unique("wihtdrawal", check_unique):
        db.setdefault("withdrawal", {})["reference_id"] = check_unique
    else:
        raise HTTPException(status_code=409, detail="Existing Data")
    
    return jsend.success({"withdrawal": db.get("withdrawal")})

@app.patch("/api/v1/wallet")
async def disable_wallet(is_disabled: Annotated[bool, Form()], current_token: Token = Depends(get_current_token)):
    
    current_status = db.get("wallet", {}).get("status", "")
    if is_disabled == True:
        if current_status == "enabled":
            update_status = current_status.replace("enabled", "disabled")
            db.setdefault("wallet", {})["status"] = update_status
        else:
            raise HTTPException(status_code=409, detail="Wallet is Disabled")
    else:
        raise HTTPException(status_code=400, detail="Bad Request")

    return jsend.success({"wallet": db.get("wallet")})