# 💳 Wallet Service API

## Overview
This is a robust Node.js Express application that provides a secure wallet service, integrating with Paystack for seamless payment processing, JWT for user authentication, and a custom API key system for secure service-to-service interactions. It leverages MySQL as its primary database and features Google OAuth for user onboarding.

## Features
-   **Node.js & Express**: Built on a modern JavaScript runtime and a minimalist web framework for efficient API development.
-   **MySQL2**: Persistent and reliable data storage with `mysql2/promise` for asynchronous database operations.
-   **JWT (jsonwebtoken)**: Secure token-based authentication for user sessions, ensuring secure access to protected routes.
-   **Passport.js (Google OAuth20)**: Streamlined user registration and login experience via Google OAuth.
-   **Paystack Integration**: Facilitates secure and verified wallet deposits using Paystack's payment gateway.
-   **Custom API Key Management**: Allows users to generate and manage API keys with granular permissions and expiry, enabling secure third-party service integration.
-   **Wallet Operations**: Supports core wallet functionalities including balance retrieval, deposit processing, and internal transfers between wallets.
-   **Transaction History**: Provides a comprehensive log of all user transactions (deposits and transfers).
-   **Swagger UI**: Interactive API documentation for easy exploration and testing of all endpoints.
-   **Bcryptjs**: Robust hashing for API keys to ensure sensitive data is stored securely.

## Getting Started
To get this project up and running locally, follow these steps.

### Installation
⬇️ **Clone the Repository:**
```bash
git clone https://github.com/AjaoPeter8/Wallet-Service-with-Paystack-JWT-API-Keys-.git
cd Wallet-Service-with-Paystack-JWT-API-Keys-
```

📦 **Install Dependencies:**
```bash
npm install
```

🛠️ **Initialize Database Schema:**
This command will connect to your configured MySQL database and create the necessary tables (`users`, `wallets`, `transactions`, `api_keys`).
```bash
npm run init-db
```

### Environment Variables
Create a `.env` file in the root directory and populate it with the following required variables. Examples are provided for clarity.

```dotenv
# Server Configuration
PORT=3000
SESSION_SECRET="your_express_session_secret_key" # Replace with a strong, unique secret

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=""
DB_NAME=wallet_service

# JWT Authentication
JWT_SECRET="your_jwt_secret_key" # Replace with a strong, unique secret

# Google OAuth Configuration
GOOGLE_CLIENT_ID="your_google_client_id"
GOOGLE_CLIENT_SECRET="your_google_client_secret"

# Paystack API Configuration
PAYSTACK_SECRET="sk_test_your_paystack_secret_key_here" # Your Paystack Secret Key
```

## API Documentation
The API is designed to be intuitive and RESTful, allowing users to manage their wallets and API keys securely.

### Base URL
*   **Production**: `https://wallet-service-with-paystack-jwt-api-keys-production.up.railway.app`
*   **Development**: `http://localhost:3000`

### Endpoints

#### GET /auth/google
Initiates the Google OAuth authentication flow.

**Request**:
None

**Response**:
`302 Redirect` to Google's authentication page.

**Errors**:
-   N/A (This endpoint performs a redirect).

---

#### GET /auth/google/callback
Handles the callback from Google OAuth after successful authentication, creates/updates user and wallet, and issues a JWT.

**Request**:
Google OAuth callback parameters (handled automatically by Passport.js).

**Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEwMTIzNDU2Nzg5MDEyMzQ1Njc4OSIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.exampleJWTtoken12345",
  "user": {
    "id": "101234567890123456789",
    "email": "user@example.com",
    "name": "User Name"
  }
}
```

**Errors**:
-   `500 Internal Server Error`: `{"error": "Database error", "details": "Error message"}`

---

#### POST /keys/create
Creates a new API key for the authenticated user with specified permissions and expiry. Requires user (JWT) authentication.

**Request**:
```json
{
  "name": "MyBillingIntegration",
  "permissions": ["read", "deposit"],
  "expiry": "1M"
}
```
**Required Fields**:
-   `name`: `string` - A unique name for the API key.
-   `expiry`: `string` - The duration until the key expires. Valid values: `1H`, `1D`, `1M`, `1Y`.
-   `permissions`: `array` of `string` (optional) - An array of permissions (e.g., `["read", "deposit", "transfer"]`). If omitted, no specific permissions are assigned.

**Response**:
```json
{
  "api_key": "sk_live_example_api_key_here",
  "expires_at": "2024-11-27T10:00:00.000Z"
}
```

**Errors**:
-   `403 Forbidden`: `{"error": "Only users can create API keys"}`
-   `400 Bad Request`: `{"error": "Missing required fields"}`
-   `400 Bad Request`: `{"error": "API key name already exists"}`
-   `400 Bad Request`: `{"error": "Maximum 5 active API keys allowed"}`
-   `500 Internal Server Error`: `{"error": "Database error", "details": "Error message"}`

---

#### POST /keys/rollover
Generates a new API key for an expired key, retaining its name and permissions. Requires user (JWT) authentication.

**Request**:
```json
{
  "expired_key_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "expiry": "1M"
}
```
**Required Fields**:
-   `expired_key_id`: `string` - The ID of the expired API key to roll over.
-   `expiry`: `string` - New expiry duration for the rolled-over key. Valid values: `1H`, `1D`, `1M`, `1Y`.

**Response**:
```json
{
  "api_key": "sk_live_new_example_api_key_here",
  "expires_at": "2024-11-27T10:00:00.000Z"
}
```

**Errors**:
-   `404 Not Found`: `{"error": "Expired key not found"}`
-   `500 Internal Server Error`: `{"error": "Database error"}`

---

#### DELETE /keys/:name
Revokes an API key by its name, making it inactive. Requires user (JWT) authentication.

**Request**:
None (API key name passed as a URL parameter).

**Response**:
```json
{
  "message": "API key revoked successfully"
}
```

**Errors**:
-   `403 Forbidden`: `{"error": "Only users can revoke API keys"}`
-   `404 Not Found`: `{"error": "API key not found"}`
-   `500 Internal Server Error`: `{"error": "Database error"}`

---

#### POST /wallet/deposit
Initializes a deposit transaction via Paystack. Requires user (JWT) or API key authentication with `deposit` permission.

**Request**:
```json
{
  "amount": 5000
}
```
**Required Fields**:
-   `amount`: `number` - The amount to deposit (in the smallest currency unit, e.g., Kobo for NGN, but API expects Naira and converts internally).

**Response**:
```json
{
  "reference": "ref_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "authorization_url": "https://checkout.paystack.com/..."
}
```

**Errors**:
-   `400 Bad Request`: `{"error": "Invalid amount"}`
-   `500 Internal Server Error`: `{"error": "Payment initialization failed"}`
-   `401 Unauthorized`: `{"error": "No valid authentication provided"}`
-   `403 Forbidden`: `{"error": "Insufficient permissions"}`

---

#### POST /wallet/paystack/webhook
Handles incoming webhooks from Paystack to update transaction statuses and user wallet balances. This endpoint is called by Paystack and does not require authentication from the client.

**Request**:
Paystack webhook payload (example not typically provided as it's an external service call).

**Response**:
```json
{
  "status": true
}
```

**Errors**:
-   `400 Bad Request`: `{"error": "Invalid signature"}` (If `x-paystack-signature` header does not match computed hash).

---

#### GET /wallet/deposit/:reference/status
Retrieves the status of a specific deposit transaction using its reference. Requires user (JWT) authentication.

**Request**:
None (transaction reference passed as a URL parameter).

**Response**:
```json
{
  "reference": "ref_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "status": "success",
  "amount": 5000
}
```

**Errors**:
-   `404 Not Found`: `{"error": "Transaction not found"}`
-   `500 Internal Server Error`: `{"error": "Database error"}`
-   `401 Unauthorized`: `{"error": "No valid authentication provided"}`

---

#### GET /wallet/balance
Retrieves the current balance of the authenticated user's wallet. Requires user (JWT) or API key authentication with `read` permission.

**Request**:
None

**Response**:
```json
{
  "balance": 15000.75
}
```

**Errors**:
-   `500 Internal Server Error`: `{"error": "Database error"}`
-   `401 Unauthorized`: `{"error": "No valid authentication provided"}`
-   `403 Forbidden`: `{"error": "Insufficient permissions"}`

---

#### POST /wallet/transfer
Initiates a transfer of funds from the authenticated user's wallet to another specified wallet. Requires user (JWT) or API key authentication with `transfer` permission.

**Request**:
```json
{
  "wallet_number": "1234567890123",
  "amount": 2500
}
```
**Required Fields**:
-   `wallet_number`: `string` - The wallet number of the recipient.
-   `amount`: `number` - The amount to transfer.

**Response**:
```json
{
  "status": "success",
  "message": "Transfer completed"
}
```

**Errors**:
-   `400 Bad Request`: `{"error": "Invalid parameters"}`
-   `200 OK`: `{"error": "Insufficient balance"}` (Note: This error is returned with a 200 status code as per current implementation).
-   `404 Not Found`: `{"error": "Recipient wallet not found"}`
-   `400 Bad Request`: `{"error": "Cannot transfer to own wallet"}`
-   `500 Internal Server Error`: `{"error": "Database error"}`
-   `401 Unauthorized`: `{"error": "No valid authentication provided"}`
-   `403 Forbidden`: `{"error": "Insufficient permissions"}`

---

#### GET /wallet/transactions
Retrieves a list of all transactions (deposits and transfers) for the authenticated user, ordered by creation date. Requires user (JWT) or API key authentication with `read` permission.

**Request**:
None

**Response**:
```json
[
  {
    "type": "deposit",
    "amount": 10000,
    "status": "success",
    "createdAt": "2024-10-26T14:30:00.000Z"
  },
  {
    "type": "transfer",
    "amount": 2500,
    "status": "success",
    "createdAt": "2024-10-26T10:15:00.000Z"
  }
]
```

**Errors**:
-   `500 Internal Server Error`: `{"error": "Database error"}`
-   `401 Unauthorized`: `{"error": "No valid authentication provided"}`
-   `403 Forbidden`: `{"error": "Insufficient permissions"}`

---

## Contributing
We welcome contributions to enhance this project! If you're interested in improving the Wallet Service API, please follow these guidelines:

🤝 **Fork the Repository**: Start by forking this repository to your GitHub account.

🌳 **Create a Feature Branch**:
```bash
git checkout -b feature/your-feature-name
```
Give your branch a descriptive name (e.g., `feature/add-two-factor-auth` or `fix/database-connection`).

🚀 **Commit Your Changes**: Make your changes, ensure they adhere to the project's coding style, and write clear, concise commit messages.
```bash
git commit -m 'feat: Implement new feature'
```

⬆️ **Push to Your Branch**:
```bash
git push origin feature/your-feature-name
```

💡 **Open a Pull Request**: Once your changes are ready, open a pull request to the `main` branch of this repository. Describe your changes clearly and link to any relevant issues.

## License
This project is licensed under the ISC License. See the `package.json` file for details.

## Author Info
**Ajao Peter Oluwafemi**
*   LinkedIn: [Your LinkedIn Profile]
*   Twitter: [Your Twitter Handle]

## Badges
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![Paystack](https://img.shields.io/badge/Paystack-00C3F7?style=for-the-badge&logo=paystack&logoColor=white)](https://paystack.com/)
[![ISC License](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)

[![Readme was generated by Dokugen](https://img.shields.io/badge/Readme%20was%20generated%20by-Dokugen-brightgreen)](https://www.npmjs.com/package/dokugen)