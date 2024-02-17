### ![image](https://github.com/SandQuattro/golang-sso/assets/31468131/4454c9ac-4dcd-405a-a3cf-8e92cb2bd170)
# Single Sign-on API
#### Version 1.0

## Common

### About service
The Single Sign-On API (here and after referred to as *API*) provides a set of methods necessary for
registration / authorization of users in the company's systems, refreshing the jwt token, as well as user management methods, like change password, email password renewal...

Also providing oauth authorization through such systems as Google, VK, Mail.ru, using OAuth2.0 protocol specification (rfc6749)

Technologies:

Main alghorithm: Argon2 with salt hashing alghorithm. Argon2 is a cryptographic hashing algorithm specifically used to hash passwords. It provides better protection against password cracking than other hashing algorithms like Bcrypt, Scrypt, etc...

Microservice core: Echo web microframework v4

Authorization: JWT token, created using pre-generated keypairs, can be validated on other company's services using public key. 

Configuration: Hocon config

Logging: LogDoc logging subsystem

Migrations: golang-migrate

Communication Bus: Asynq (Redis-based async queue) for incidents notification by telegram, sending emails, etc. 

Database: Postgres, using sqlx and some sqlc database access code generation

Can be deployed to Docker, Dockerfile included

Observalibity: 

- Opentracing to Jaeger UI or my custom trace collector with LogDoc trace processing
- Prometheus metrics (golang standart + custom business metrics) with Grafana visualization
- LogDoc logging visualization
- Asynq queue monitoring using asynqmon 

### Middlewares, Features

Rate limiter middleware, rate limit: 20 rps/sec, burst: 20 (maximum number of requests to pass at the same moment)

Teler WAF (Intrusion Detection Middleware) https://github.com/kitabisa/teler-waf.git

LogDoc logging subsystem, ClickHouse-based high performance logging collector https://logdoc.org/en/

pprof profiling in debug mode

Graceful shutdown

### Building

Using Makefile:  make rebuild, restart, run, etc

### Future plans

- move oauth to separate table, one user can have muptiple oauth accounts
- add refresh token with db storage
- uber zap logging
- sliding salt position
- rereading config using SIGHUP signal
- gRPC other services integration
