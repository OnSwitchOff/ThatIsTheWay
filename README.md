# AuthService

## Overview
AuthService provides authentication, registration, and user management APIs for the system.

## Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- SQL Server (or compatible database)
- Docker (optional, for containerized deployment)

## Setup

1. **Clone the repository:**
	```bash
	git clone <your-repo-url>
	```

2. **Navigate to the AuthService directory:**
	```bash	
	cd AuthService
	```

3. **Restore dependencies:**
	```bash
	dotnet restore
	```

4. **Apply database migrations:**
   Ensure your connection string in `appsettings.js	on` is correct.
	```bash
	dotnet ef database update
	```

5. **Run the service:**	
	```bash
	dotnet run
	```

6. **Access Swagger UI for API documentation:**
Open [http://localhost:5000/swagger](http://localhost:5000/swagger) (or the port specified in `launchSettings.json`).

## API Endpoints

Swagger/OpenAPI is enabled. Main endpoints include:

- `POST /api/auth/register`  
Register a new user.  
**Request:** `RegisterRequest` (email, password, etc.)  
**Response:** Success or error message.

- `POST /api/auth/login`  
Authenticate a user.  
**Request:** `LoginRequest` (email, password)  
**Response:** `LoginResponse` (JWT token, user info).

- `POST /api/auth/confirm-email`  
Confirm user email with token.

- `POST /api/auth/lockout` 
Lock out a user after failed attempts.

- `GET /api/auth/profile`  
Get current user profile (requires authentication).

See Swagger UI for full details and try out endpoints interactively.

## Environment Variables

Configuration is managed via `appsettings.json` and environment variables. Key settings:

- `ConnectionStrings:DefaultConnection` – SQL Server connection string
- `Jwt:Key` – Secret key for JWT token generation
- `Jwt:Issuer` – JWT issuer
- `Jwt:Audience` – JWT audience
- `Email:SmtpServer`, `Email:Port`, `Email:Username`, `Email:Password` – SMTP settings for email confirmation

## Testing

Run unit tests:
	```
	dotnet test
	```

## Docker

To build and run with Docker:
	```
	docker build -t authservice . docker run -p 5000:80 authservice
	```

## Contributing

- Follow C# 12 and .NET 8 coding standards.
- Document public APIs with XML comments.
- Use Swagger for endpoint documentation.
