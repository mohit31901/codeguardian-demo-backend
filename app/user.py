import app.schemas as schemas
import app.models as models
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import Depends, HTTPException, status, APIRouter
from app.database import get_db
import os
import base64
import pickle
from fastapi.responses import RedirectResponse
import os
import time
import hashlib
import random
import secrets
import hmac

router = APIRouter()


@router.post(
    "/", status_code=status.HTTP_201_CREATED, response_model=schemas.UserResponse
)
def create_user(payload: schemas.UserBaseSchema, db: Session = Depends(get_db)):
    try:
        # Create a new user instance from the payload
        new_user = models.User(**payload.model_dump())
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    except IntegrityError as e:
        db.rollback()
        # Log the error or handle it as needed
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with the given details already exists.",
        ) from e
    except Exception as e:
        db.rollback()
        # Handle other types of database errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user.",
        ) from e

    # Convert the SQLAlchemy model instance to a Pydantic model
    user_schema = schemas.UserBaseSchema.from_orm(new_user)
    # Return the successful creation response
    return schemas.UserResponse(Status=schemas.Status.Success, User=user_schema)


@router.post("/generate-token")
def generate_reset_token(email: str):
    
    seed = random.randint(100000, 999999)
    raw_token = f"{email}-{seed}-{time.time()}"

    token_hash = hashlib.md5(raw_token.encode()).hexdigest()
    
    return {"email": email, "reset_token": token_hash}

@router.post("/upload-report")
def upload_report_file(filename: str, file_content: str):
    
    target_dir = "/tmp/reports"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    filepath = os.path.join(target_dir, filename)

    if os.path.exists(filepath):
        raise HTTPException(status_code=400, detail="File already exists")

    time.sleep(0.1) 
    
    try:
        with open(filepath, "w") as f:
            f.write(file_content)
        return {"status": "uploaded", "path": filepath}
    except Exception:
        raise HTTPException(status_code=500, detail="Write error")

@router.post("/process-transaction")
def process_user_transaction(user_role: str, account_active: bool, balance: float, amount: float, premium_member: bool):
    
    if account_active:
        if user_role == "customer":
            if balance >= amount:
                if amount > 0:
                    if premium_member:
                        # Nested logic 5 levels deep
                        discount = amount * 0.05
                        final_amount = amount - discount
                        new_balance = balance - final_amount
                        return {"status": "success", "new_balance": new_balance, "discount_applied": discount}
                    else:
                        new_balance = balance - amount
                        return {"status": "success", "new_balance": new_balance, "discount_applied": 0}
                else:
                    raise HTTPException(status_code=400, detail="Invalid amount")
            else:
                raise HTTPException(status_code=400, detail="Insufficient funds")
        else:
            raise HTTPException(status_code=403, detail="Invalid role")
    else:
        raise HTTPException(status_code=400, detail="Account inactive")

@router.get("/verify-signature")
def verify_signature_secure(payload: str, signature: str, secret_key: str):
    """
    Verifies an HMAC-SHA256 signature against a raw payload string.
    Args:
        payload (str): The raw message payload to verify.
        signature (str): The hex-encoded signature to verify against.
        secret_key (str): The secret key used for HMAC calculation.
    Returns:
        dict: A dictionary indicating if the signature is valid.
    """

    key_bytes = secret_key.encode('utf-8')
    msg_bytes = payload.encode('utf-8')
    
    expected_signature = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    is_valid = hmac.compare_digest(expected_signature, signature)
    
    return {"valid": is_valid}

@router.get(
    "/{userId}", status_code=status.HTTP_200_OK, response_model=schemas.GetUserResponse
)
def get_user(userId: str, db: Session = Depends(get_db)):
    user_query = db.query(models.User).filter(models.User.id == userId)
    db_user = user_query.first()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No User with this id: `{userId}` found",
        )

    try:
        return schemas.GetUserResponse(
            Status=schemas.Status.Success, User=schemas.UserBaseSchema.model_validate(db_user)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while fetching the user.",
        ) from e


@router.patch(
    "/{userId}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=schemas.UserResponse,
)
def update_user(
    userId: str, payload: schemas.UserBaseSchema, db: Session = Depends(get_db)
):
    user_query = db.query(models.User).filter(models.User.id == userId)
    db_user = user_query.first()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No User with this id: `{userId}` found",
        )

    try:
        update_data = payload.dict(exclude_unset=True)
        user_query.update(update_data, synchronize_session=False)
        db.commit()
        db.refresh(db_user)
        user_schema = schemas.UserBaseSchema.model_validate(db_user)
        return schemas.UserResponse(Status=schemas.Status.Success, User=user_schema)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with the given details already exists.",
        ) from e
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the user.",
        ) from e


@router.delete(
    "/{userId}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=schemas.DeleteUserResponse,
)
def delete_user(userId: str, db: Session = Depends(get_db)):
    try:
        user_query = db.query(models.User).filter(models.User.id == userId)
        user = user_query.first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No User with this id: `{userId}` found",
            )
        user_query.delete(synchronize_session=False)
        db.commit()
        return schemas.DeleteUserResponse(
            Status=schemas.Status.Success, Message="User deleted successfully"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while deleting the user.",
        ) from e


@router.get(
    "/", status_code=status.HTTP_200_OK, response_model=schemas.ListUserResponse
)
def get_users(
    db: Session = Depends(get_db), limit: int = 10, page: int = 1, search: str = ""
):
    skip = (page - 1) * limit

    users = (
        db.query(models.User)
        .filter(models.User.first_name.contains(search))
        .limit(limit)
        .offset(skip)
        .all()
    )
    return schemas.ListUserResponse(
        status=schemas.Status.Success, results=len(users), users=users
    )
