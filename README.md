JWKS Server Project
This project implements a JSON Web Key Set (JWKS) Server using Flask and RSA key pairs. It provides public keys for verifying JWTs, handles key expiration, and supports issuing valid and expired JWTs.

Features
Generates and manages RSA key pairs dynamically.
Serves JWKS at /.well-known/jwks.json, excluding expired keys.
Issues JWTs via /auth, with an option to generate expired tokens.
Ensures compliance with proper HTTP methods and status codes.

Setup Instructions:
1️⃣ Clone the Repository

2️⃣ Install Dependencies
Make sure you have Python 3 installed. Then run:
pip install -r requirements.txt

3️⃣ Run the Server
python3 app.py
By default, the server runs on http://127.0.0.1:8080.


Testing the API

1️⃣ Generate a JWT
curl -X POST http://127.0.0.1:8080/auth

2️⃣ Get Public JWKS Keys
curl http://127.0.0.1:8080/.well-known/jwks.json

3️⃣ Generate an Expired JWT
curl -X POST http://127.0.0.1:8080/auth?expired=true

Running the Gradebot Test
Run the following command inside your project folder:
./gradebot project1

Notes:
The server automatically removes expired keys from JWKS.
The expired=true query parameter ensures the expired token is generated properly.
Ensure Python 3 is installed before running the server.
