# auth-service

Stores user credentials and issues JWT tokens. Part of the Innowise microservices.

## Endpoints

All endpoints are under `/api/v1/auth`.

| Method | Path | Description |
|---|---|---|
| POST | `/register` | Create credentials, returns access and refresh tokens |
| POST | `/login` | Returns access and refresh tokens |
| POST | `/refresh` | New token pair by refresh token |
| POST | `/validate` | Checks access token, returns user id and role |
| DELETE | `/credentials` | Internal, see below |

`DELETE /credentials` deletes the user from the access token in the `Authorization` header. It is used only by the API Gateway to roll back a registration when the user profile could not be created. The gateway does not route it to clients. The admin account cannot be deleted (403).

## Environment variables

Copy `.env.example` to `.env` and fill in the values.

| Variable | Description |
|---|---|
| `DB_HOST`, `DB_PORT`, `DB_NAME` | PostgreSQL connection |
| `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL credentials |
| `JWT_SECRET` | Base64 key, at least 32 bytes after decoding |
| `JWT_ACCESS_TOKEN_TTL`, `JWT_REFRESH_TOKEN_TTL` | Token lifetime, e.g. `15m`, `7d` |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Admin account created on startup |

A secret can be generated in PowerShell:

```
[Convert]::ToBase64String((1..64 | ForEach-Object { Get-Random -Maximum 256 }))
```

## Running

Locally (database in Docker, app from IDE with the `local` profile):

```
docker compose up -d postgres
```

Everything in Docker:

```
docker compose up --build
```

The service runs on port 8081.

## Tests

```
mvn verify
```

Integration tests use Testcontainers, so Docker has to be running.
