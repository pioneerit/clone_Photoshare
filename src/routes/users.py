from fastapi import APIRouter, Depends

from src.database.models import User
from src.services.auth import auth_service
from src.schemas import UserResponse
# from src.services.roles import RoleAccess


from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from src.config.detail import USER_BANNED, PRIVILEGES_DENIED
from src.database.db import get_db
from src.database.models import User
from src.schemas import UserDb, UpdateUser, UserModel, UserResponse, UserInfoResponse, UserBanned
from src.services.auth import auth_service

from src.repository import users as repository_users

user_router = APIRouter(prefix="/user", tags=['users'])

security = HTTPBearer()

# allowed_get_user = RoleAccess([Role.admin, Role.moder, Role.user])
# allowed_create_user = RoleAccess([Role.admin, Role.moder, Role.user])
# allowed_get_all_users = RoleAccess([Role.admin])
# allowed_remove_user = RoleAccess([Role.admin])
# allowed_ban_user = RoleAccess([Role.admin])
# allowed_change_user_role = RoleAccess([Role.admin])

@user_router.get("/me/", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(auth_service.get_current_user)):
    """
    The **read_users_me** function is a GET endpoint that returns the current user's information.
    It uses the auth_service to get the current user, and then returns it.

    :param current_user: User: Get the current user
    :return: The current user object
    """
    return current_user

# @user_router.post('/create_test', response_model=UserResponse)
# async def create_one_user(body: UserModel, db: Session = Depends(get_db)):
#     exist_user = await repository_users.get_user_by_email(body.email, db)
#     if exist_user:
#         raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")
#     new_user = await repository_users.create_one_user(body, db)
#     return {"user": new_user, "detail": "User successfully created"}


@user_router.put('/edit', response_model=UserDb)
async def update_user_info(body: UpdateUser, current_user: User = Depends(auth_service.get_current_user),
                           db: Session = Depends(get_db)):
    """
    Edit information of user

    :param body: new data
    :type body: UpdateUser
    :param current_user: user whose info is changing
    :type current_user: User
    :param db: The database session
    :type db: Session
    :return: updated user
    :rtype: User
    """

    user = await repository_users.update_user_info(email=current_user.email, body=body, db=db)
    return user


@user_router.get('/info', response_model=UserInfoResponse)
async def user_info(db: Session = Depends(get_db),
                    current_user: User = Depends(auth_service.get_current_user)):
    """
    Get user info

    :param current_user: user whose info is changing
    :type current_user: User
    :param db: The database session
    :type db: Session
    :return: user info
    :rtype: dict
    """

    user_info = await repository_users.get_user_info(current_user, db)
    return user_info


@user_router.put('/ban/{id_}', response_model=UserBanned)
async def ban_user(id_, db: Session = Depends(get_db), current_user: User = Depends(auth_service.get_current_user)):
    """
    Ban user

    :param current_user: user whose info is changing
    :type current_user: User
    :param db: The database session
    :type db: Session
    :return: banned user info with message of success
    :rtype: dict
    """
    print('current user role', str(current_user.roles))
    if str(current_user.roles) != "Role.admin":
        raise HTTPException(status_code=403, detail=PRIVILEGES_DENIED)
    banned_user = await repository_users.ban_user(id_, db)
    return {"user": banned_user, "detail": USER_BANNED}

# @router.get("/all", response_model=List[UserDb], dependencies=[Depends(allowed_get_all_users)])
# async def read_all_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
#     """
#     The **read_all_users** function returns a list of users.
#         ---
#         get:
#           summary: Returns all users.
#           description: This can only be done by the logged in user.
#           operationId: read_all_users
#           parameters:
#             - name: skip (optional)  # The number of records to skip before returning results, default is 0 (no records skipped).  Used for pagination purposes.   See https://docs.mongodb.com/manual/reference/method/cursor.skip/#cursor-skip-examples for more information on how this
#
#     :param skip: int: Skip the first n records
#     :param limit: int: Limit the number of results returned
#     :param db: Session: Pass the database connection to the function
#     :return: A list of users
#     """
#     users = await repository_users.get_users(skip, limit, db)
#     return users

# @router.get("/commented_images_by_me/", response_model=List[ImageResponse])
# async def read_commented_images_by_me(db: Session = Depends(get_db),
#                                      current_user: User = Depends(auth_service.get_current_user)):
#     """
#     The **read_commented_images_by_me** function returns all images that the current user has commented on.
#
#     :param db: Session: Get the database session
#     :param current_user: User: Get the user that is currently logged in
#     :return: A list of images that the user has commented on
#     """
#     images = await repository_users.get_all_commented_images(current_user, db)
#     if not images:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
#     return images

# @router.get("/rated_images_by_me/", response_model=List[ImageResponse])
# async def read_liked_images_by_me(db: Session = Depends(get_db),
#                                  current_user: User = Depends(auth_service.get_current_user)):
#     """
#     The **read_liked_images_by_me** function returns all images liked by the current user.
#         The function is called when a GET request is made to the /users/me/liked_images endpoint.
#
#     :param db: Session: Pass the database connection to the function
#     :param current_user: User: Get the user object of the current logged in user
#     :return: A list of images that the user liked
#     """
#     images = await repository_users.get_all_liked_images(current_user, db)
#     if not images:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
#     return images