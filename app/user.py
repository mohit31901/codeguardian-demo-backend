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
import logging
import hashlib
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

router= APIRouter()

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

@router.get("/safe-read")
def read_file_safe(file_path: str):
    """
    Safely reads and returns the contents of a text file within the reports directory.
    Args:
        file_path (str): The relative path of the file to read.
    Returns:
        dict: A dictionary containing the file contents.
    Raises:
        HTTPException: 403 error if the path attempts directory traversal.
    """
    
    base_dir = Path("/tmp/reports").resolve()
    target_path = (base_dir / file_path).resolve()
    
    if not target_path.is_relative_to(base_dir):
        raise HTTPException(status_code=403, detail="Access denied: Directory traversal blocked")
        
    with open(target_path, "r") as f:
        content = f.read()
        
    return {"content": content}

@router.post("/execute-utility")
def run_system_utility(utility_name: str, args: str):
 
    command_string = f"{utility_name} {args}"
    
    process = subprocess.Popen(command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    return {"stdout": stdout.decode(), "stderr": stderr.decode()}

@router.post("/parse-config")
def parse_xml_config(xml_data: str):
   
    parser = ET.XMLParser()
    root = ET.fromstring(xml_data, parser=parser)
    
    config_dict = {}
    for child in root:
        config_dict[child.tag] = child.text
        
    return {"configuration": config_dict}

@router.post("/write-audit-log")
def append_audit_log(log_message: str):

    log_dir = "/tmp/logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        
    f = open(os.path.join(log_dir, "audit.log"), "a")
    f.write(f"{time.time()}: {log_message}\n")
    
    return {"status": "logged"}

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
