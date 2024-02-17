### ![image](https://github.com/SandQuattro/golang-sso/assets/31468131/4454c9ac-4dcd-405a-a3cf-8e92cb2bd170)
# Single Sign-on API
#### Version 1.0

## Common

### About service
The Single Sign-On API (here and after referred to as *API*) provides a set of methods necessary for
registration / authorization of users in the company's systems, refreshing the jwt token, as well as user management methods, like change password, email password renewal...

Also providing oauth authorization through such systems as Google, VK, Mail.ru, using OAuth2.0 protocol specification (rfc6749)

Technologies:

**Microservice core:** Echo web microframework v4

**Authorization**: JWT token, created using pre-generated keypairs, can be validated on other company's services using public key. 

**Configuration**: Hocon config

**Logging**: LogDoc logging subsystem

**Migrations**: golang-migrate

**Communication Bus:** Asynq (Redis-based async queue) for incidents notification by telegram, sending emails, etc. 

**Database**: Postgres, using sqlx and some sqlc database access code generation

Can be deployed to **Docker**, Dockerfile included

**Observalibity**: 

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

### **Alghoritms**:

**Main alghorithm**: Argon2 with salt hashing alghorithm. Argon2 is a cryptographic hashing algorithm specifically used to hash passwords. It provides better protection against password cracking than other hashing algorithms like Bcrypt, Scrypt, etc...

**SHA-256**

The SHA-256 hashing algorithm (Secure Hash Algorithm 256-bit) is part of the SHA-2 family of cryptographic hash functions developed by the US National Institute of Standards and Technology (NIST). SHA-256 generates a unique 256-bit (32-byte) hash from data of any size, making it widely used in various security and cryptography systems such as digital signatures, blockchain, and data integrity verification.

**SHA-256 hashing process:**
The algorithm processes the input data in blocks of 512 bits (64 bytes) and goes through a series of cryptographic transformations to produce a final hash of 256 bits. The whole process can be described in the following steps:

Data Preparation: The input data is padded to a length of 448 modulo 512. Padding starts with a '1' bit followed by '0' bits until the length is reached. After this, another 64 bits are added, representing the original length of the input data in bits.

Hash Initialization: The algorithm is initialized with the eight initial hash values (h0-h7) provided in the SHA-256 specification. These values are the first 32 bits of the fractional parts of the square roots of the first eight prime numbers.

Main loop: Auxiliary functions and operations such as sigma and maj are introduced. The data is processed in a main loop consisting of 64 rounds. Each round uses different bit manipulations and transformations on pieces of data and hashes. The round constants for each round come from the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.

Adding the calculated hash to the final result: Upon completion of the main loop, the result of the transformations in each block is added to the result of the previous block. This is achieved by adding to each of the eight hash values (h0-h7) in turn.

Output of the final hash: After processing all the blocks, the final value consists of a concatenation of eight hash values (h0-h7), representing a 256-bit hash.

### Features of SHA-256:

**Collision resistance**: There are currently no known effective attacks that can find two different data sets with the same SHA-256 hash.

**Determinism**: For the same input data, SHA-256 always produces the same hash.
**Avalanche effect**: Changing even one bit of the input results in a completely different and unrecognizable hash.
**High Performance**: SHA-256 is designed to enable **fast hash computation** on a wide range of hardware.
SHA-256 is the basis of many modern security technologies and is widely used in cryptography, including authentication protocols, blockchain systems, etc.

### Building

Using Makefile:  make rebuild, restart, run, etc

### Future plans

- move oauth to separate table, one user can have muptiple oauth accounts
- add refresh token with db storage
- uber zap logging
- sliding salt position
- rereading config using SIGHUP signal
- gRPC other services integration
