from motor.motor_asyncio import AsyncIOMotorCollection


class UserRepository:
    def __init__(self, collection: AsyncIOMotorCollection):
        self.collection = collection

    async def create_indexes(self) -> None:
        await self.collection.create_index("email", unique=True)

    async def get_by_email(self, email: str) -> dict | None:
        return await self.collection.find_one({"email": email}, {"_id": 0})

    async def create_user(self, user_data: dict) -> None:
        await self.collection.insert_one(user_data)

    async def update_login_failure_state(
        self,
        email: str,
        failed_login_attempts: int,
        login_locked_until: str | None,
    ) -> None:
        await self.collection.update_one(
            {"email": email},
            {
                "$set": {
                    "failed_login_attempts": failed_login_attempts,
                    "login_locked_until": login_locked_until,
                }
            },
        )

    async def reset_login_failure_state(self, email: str) -> None:
        await self.collection.update_one(
            {"email": email},
            {
                "$set": {
                    "failed_login_attempts": 0,
                    "login_locked_until": None,
                }
            },
        )

    async def update_password(
        self,
        email: str,
        hashed_password: str,
        password_changed_at: str,
    ) -> None:
        await self.collection.update_one(
            {"email": email},
            {
                "$set": {
                    "password": hashed_password,
                    "password_changed_at": password_changed_at,
                    "failed_login_attempts": 0,
                    "login_locked_until": None,
                }
            },
        )

    async def get_public_by_email(self, email: str) -> dict | None:
        return await self.collection.find_one(
            {"email": email},
            {"_id": 0, "password": 0},
        )
