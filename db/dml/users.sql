-- name: ListUsers :many
SELECT id,
       coalesce(auth_system, '') as auth_system,
       coalesce(sub, '')         as sub,
       name,
       given_name,
       family_name,
       coalesce(avatar, '')      as avatar,
       email,
       email_verified,
       coalesce(locale, '')      as locale,
       hashed_password,
       role
FROM users
ORDER BY id
LIMIT $1 OFFSET $2;

-- name: FindUserBySub :one
SELECT id,
       coalesce(sub, '')    as sub,
       name,
       given_name,
       family_name,
       coalesce(avatar, '') as avatar,
       email,
       email_verified,
       coalesce(locale, '') as locale,
       hashed_password,
       role
FROM users u
WHERE u.sub = $1;

-- name: FindUserById :one
SELECT u.id,
       COALESCE(u.auth_system, '')     as auth_system,
       COALESCE(u.sub, '')             as sub,
       COALESCE(u.name, '')            as name,
       COALESCE(u.given_name, '')      as given_name,
       COALESCE(u.family_name, '')     as family_name,
       COALESCE(u.avatar, '')          as avatar,
       COALESCE(u.email, '')           as email,
       u.email_verified,
       COALESCE(u.locale, '')          as locale,
       COALESCE(u.hashed_password, '') as hashed_password,
       COALESCE(u.role, '')            as role
FROM users u
WHERE u.id = $1;

-- name: FindUserByLogin :one
SELECT u.id,
       COALESCE(u.auth_system, '')     as auth_system,
       COALESCE(u.sub, '')             as sub,
       COALESCE(u.name, '')            as name,
       COALESCE(u.given_name, '')      as given_name,
       COALESCE(u.family_name, '')     as family_name,
       COALESCE(u.avatar, '')          as avatar,
       COALESCE(u.email, '')           as email,
       u.email_verified,
       COALESCE(u.locale, '')          as locale,
       COALESCE(u.hashed_password, '') as hashed_password,
       COALESCE(u.role, '')            as role
FROM users u
WHERE u.email = $1;

-- name: FindUserByLoginAndSystem :one
SELECT u.id,
       COALESCE(u.auth_system, '')     as auth_system,
       COALESCE(u.sub, '')             as sub,
       COALESCE(u.name, '')            as name,
       COALESCE(u.given_name, '')      as given_name,
       COALESCE(u.family_name, '')     as family_name,
       COALESCE(u.avatar, '')          as avatar,
       COALESCE(u.email, '')           as email,
       u.email_verified,
       COALESCE(u.locale, '')          as locale,
       COALESCE(u.hashed_password, '') as hashed_password,
       COALESCE(u.role, '')            as role
FROM users u
WHERE u.email = $1
  AND u.auth_system = $2;

-- name: CreateUser :one
INSERT INTO users(auth_system,
                  name,
                  family_name,
                  given_name,
                  email,
                  email_verified,
                  hashed_password,
                  role,
                  valid_till)
VALUES ('direct',
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8)
RETURNING *;

-- name: CreateGoogleUser :one
INSERT INTO users(auth_system,
                  sub,
                  name,
                  given_name,
                  family_name,
                  avatar,
                  email,
                  email_verified,
                  locale,
                  hashed_password,
                  role,
                  valid_till)
VALUES ('google',
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        'user',
        $10)
RETURNING *;

-- name: UpdateUser :exec
UPDATE users
SET auth_system     = $2,
    sub             = $3,
    name            = $4,
    given_name      = $5,
    family_name     = $6,
    avatar          = $7,
    email           = $8,
    email_verified  = $9,
    locale          = $10,
    hashed_password = $11,
    role            = $12,
    valid_till      = $13
WHERE id = $1;

-- name: DeleteUser :exec
DELETE
FROM users
WHERE id = $1;
