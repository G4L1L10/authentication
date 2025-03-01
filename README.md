## Register a user

curl -X POST http://localhost:8080/auth/register -H "Content-Type: application/json" -d '{
"email": "admin@example.com",
"password": "securepassword"
}'

## Login a user

curl -X POST http://localhost:8080/auth/login -H "Content-Type: application/json" -d '{
"email": "admin@example.com",
"password": "securepassword"
}'

## Get a User (Protected Route)

curl -X GET http://localhost:8080/users/{user_id} -H "Authorization: Bearer {your_jwt_token}"

## Delete a user from the database console

DELETE FROM users WHERE id = '';
