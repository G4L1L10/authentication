## Register a user

curl -X POST http://localhost:8080/auth/register -H "Content-Type: application/json" -d '{
"email": "@email.com",
"password": "securepassword"
}'

## Login a user

curl -X POST http://localhost:8080/auth/login -H "Content-Type: application/json" -d '{
"email": "admin@email.com",
"password": "securepassword"
}'

## Get a User (Protected Route)

curl -X GET http://localhost:8080/users/{user_id} -H "Authorization: Bearer {your_jwt_token}"

## Delete a user from the database console

## Logouts a user

curl -X POST http://localhost:8080/auth/logout -H "Authorization: Bearer <YOUR_REFRESH_TOKEN>"

DELETE FROM users WHERE id = '';
