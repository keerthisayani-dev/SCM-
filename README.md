# SCMXPertLite

SCMXPertLite is a FastAPI-based backend with MongoDB for authentication, role-based access, and future SCM modules such as devices and shipments.

## Current scope

- FastAPI app factory with `/health`, `/info`, and `/ping-db`
- MongoDB integration with `users`, `devices`, and `shipments` collections
- Signup, login, JWT auth, password change, and protected `/me`
- Role-protected admin user management routes
- Request ID middleware and structured logging

## Run locally

1. Create and activate a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Copy `.env.example` to `.env` and fill in your values.
4. Start the server with `python run.py`.

## Main API routes

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `GET /api/admin/users`
- `PATCH /api/admin/users/{user_id}/role`
- `DELETE /api/admin/users/{user_id}`
- `POST /api/shipments`
- `GET /api/shipments`
- `GET /api/shipments/{tracking_id}`
- `PATCH /api/shipments/{tracking_id}`
- `DELETE /api/shipments/{tracking_id}`
