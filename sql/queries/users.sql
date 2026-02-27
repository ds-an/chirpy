-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
   gen_random_uuid(),
   NOW(),
   NOW(),
   $1,
   $2
)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserFromRefreshToken :one
SELECT users.*
FROM users 
INNER JOIN refresh_tokens 
ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1;

-- name: ResetUsers :exec
DELETE FROM users;
