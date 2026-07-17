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
from pydantic import BaseModel

router= APIRouter()

# Allowed language locales list (validation whitelist constant)
ALLOWED_LOCALES = {"en-US", "es-ES", "fr-FR", "de-DE", "ja-JP"}

class LocaleSettings(BaseModel):
    """
    Pydantic model representing user locale and language settings.
    """
    locale: str
    timezone: str

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

@router.post("/settings/locale")
def update_user_locale(payload: LocaleSettings):
    """
    Securely updates the application language and locale settings for a user.
    Args:
        payload (LocaleSettings): The locale settings to apply.
    Returns:
        dict: A confirmation status of the settings update.
    Raises:
        HTTPException: 400 error if the requested locale is not supported.
    """
    # 1. Validation check against whitelist to prevent malicious inputs
    if payload.locale not in ALLOWED_LOCALES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Locale '{payload.locale}' is not supported."
        )
    # 2. Secure logging of safe configuration details
    logger.info(f"User configuration updated. New locale: {payload.locale}")
    
    return {"status": "locale_updated", "active_locale": payload.locale}

@router.get("/settings/app-info")
def get_app_metadata():
    """
    Retrieves general, public application metadata and version information.
    Returns:
        dict: A dictionary containing the application name, version, and status.
    """
    # Return static, non-sensitive configuration parameters
    app_info = {
        "app_name": "CodeGuardian Demo API",
        "version": "1.2.0",
        "status": "operational"
    }
    return app_info

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
