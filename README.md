![Go Report](https://goreportcard.com/badge/github.com/SandQuattro/golang-sso-echo)
![Repository Top Language](https://img.shields.io/github/languages/top/sandquattro/golang-sso-echo)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/sandquattro/golang-sso-echo)
![Github Repository Size](https://img.shields.io/github/repo-size/sandquattro/golang-sso-echo)
![Github Open Issues](https://img.shields.io/github/issues/sandquattro/golang-sso-echo)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub last commit](https://img.shields.io/github/last-commit/sandquattro/golang-sso-echo)
![GitHub contributors](https://img.shields.io/github/contributors/sandquattro/golang-sso-echo)

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

**Observability**: 

- Opentracing to Jaeger UI or my custom trace collector with LogDoc trace processing
- Prometheus's metrics (golang standard + custom business metrics) with Grafana visualization
- LogDoc logging visualization
- Asynq queue monitoring using asynqmon 

### Middlewares, Features

- RSA, ECDSA, Ed25519 keys support (see [KEYS.md](conf/keys/KEYS.md) )
- Rate limiter middleware, rate limit: 20 rps/sec, burst: 20 (maximum number of requests to pass at the same moment)
- Teler WAF (Intrusion Detection Middleware) https://github.com/kitabisa/teler-waf.git
- LogDoc logging subsystem, ClickHouse-based high performance logging collector https://logdoc.org/en/
- pprof profiling in debug mode
- Graceful shutdown
- reading DER keys
- automatic keys rotation with redis key publishing
- longer key 4096-bit support
- add redis-based user suspicious activity detection / temporarily blocking
- redis-based registration / login locking (maintenance mode)
- refresh token with db storage / redis storage
- re-reading config using SIGHUP signal

### **Algorithms**:

#### ARGON2

Argon2 with salt hashing alghorithm. Argon2 is a cryptographic hashing algorithm specifically used to hash passwords. It provides better protection against password cracking than other hashing algorithms like Bcrypt, Scrypt, etc...

#### **SHA-256**

The SHA-256 hashing algorithm (Secure Hash Algorithm 256-bit) is part of the SHA-2 family of cryptographic hash functions developed by the US National Institute of Standards and Technology (NIST). SHA-256 generates a unique 256-bit (32-byte) hash from data of any size, making it widely used in various security and cryptography systems such as digital signatures, blockchain, and data integrity verification.

**SHA-256 hashing process:**
The algorithm processes the input data in blocks of 512 bits (64 bytes) and goes through a series of cryptographic transformations to produce a final hash of 256 bits. The whole process can be described in the following steps:

Data Preparation: The input data is padded to a length of 448 modulo 512. Padding starts with a '1' bit followed by '0' bits until the length is reached. After this, another 64 bits are added, representing the original length of the input data in bits.

Hash Initialization: The algorithm is initialized with the eight initial hash values (h0-h7) provided in the SHA-256 specification. These values are the first 32 bits of the fractional parts of the square roots of the first eight prime numbers.

Main loop: Auxiliary functions and operations such as sigma and maj are introduced. The data is processed in a main loop consisting of 64 rounds. Each round uses different bit manipulations and transformations on pieces of data and hashes. The round constants for each round come from the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.

Adding the calculated hash to the final result: Upon completion of the main loop, the result of the transformations in each block is added to the result of the previous block. This is achieved by adding to each of the eight hash values (h0-h7) in turn.

Output of the final hash: After processing all the blocks, the final value consists of a concatenation of eight hash values (h0-h7), representing a 256-bit hash.

**Features of SHA-256:**

- **Collision resistance**: There are currently no known effective attacks that can find two different data sets with the same SHA-256 hash.
- **Determinism**: For the same input data, SHA-256 always produces the same hash.
- **Avalanche effect**: Changing even one bit of the input results in a completely different and unrecognizable hash.
- **High Performance**: SHA-256 is designed to enable **fast hash computation** on a wide range of hardware.
SHA-256 is the basis of many modern security technologies and is widely used in cryptography, including authentication protocols, blockchain systems, etc.

#### **HMAC**

HMAC (Hash-based Message Authentication Code) is a type of hash-based message authentication that provides data integrity and message authentication verification using a secret key. HMAC can be used with any iterative hash function such as MD5, SHA-1, SHA-256, etc. It is widely used in various security protocols and cryptographic applications.

The basic operating principle of HMAC:
HMAC combines a hash function with a secret key to create a unique signature, which is then appended to the message. The recipient, knowing the secret key, can repeat the signature generation process with the received message and compare the result with the signature sent along with the message to verify the authenticity and integrity of the data.

HMAC Algorithm:
The HMAC generation process consists of the following steps:

Pre-preparing the key: If the length of the key is greater than the block width of the hash function being used, the key is reduced by hashing. If the key length is less, it is padded to the required length with '0' bits.

Key Conversion: The resulting key is mixed with two constant values: ipad (inner padding) and opad (outer padding). This is done by bitwise XORing the key with each of these values. ipad and opad are predefined constants.

Key ⊕ ipad: Internal key obtained by XORing the key from the ipad.
Key ⊕ opad: Foreign key obtained by XORing the key with opad.
Using a hash function:

First stage: a message is added to the “internal key”, and the hash function is applied to the result: H((Key ⊕ ipad) || message).
Second stage: the hash from the previous stage is added to the “foreign key”, and the hash function is again applied to the result: H((Key ⊕ opad) || H((Key ⊕ ipad) || message)).
Conclusion: The result of the second stage is HMAC - message authentication code.

HMAC Features and Benefits:
Security: HMAC provides both data integrity and source authentication so that the recipient can be confident that the data has not been modified in transit and that the data came from the expected party.
Flexibility: HMAC can be used with a variety of hash functions, making it a versatile security tool.
Efficiency: HMAC does not require complex calculations or additional cryptographic operations (as in asymmetric encryption), making it relatively quick to implement and use.
HMAC plays an important role in providing security and authentication in modern information systems and can be used in a variety of scenarios, from ensuring API security to verifying the authenticity of software updates and much more.

#### ARGON2 VS SHA256
**Argon2**

Argon2 is a Password Hashing Competition winner designed for secure password hashing. 

Unlike SHA-256, Argon2 is designed to protect against brute force attacks and attacks using specialized hardware such as ASICs and FPGAs. 
Argon2 has three variants: Argon2i, Argon2d and Argon2id (a hybrid of the first two).

Main characteristics of Argon2:

- **Memory Cost**: Argon2 requires a significant amount of memory to execute, making it difficult to process hashes in a massively parallel manner.
- **Configuring execution time and parallelism**: provides the ability to configure execution time and the number of parallel threads, which allows you to adapt it to specific hardware.
- **Protect against attacks using force and specialized hardware**: Time and memory costs make Argon2 difficult to attack.

**Conclusions**

SHA-256 is good for ensuring data integrity and quickly generating cryptographic hashes, but is not the best choice 
for hashing passwords due to its speed and ability to be easily cracked by force.

Argon2 is the gold standard for password hashing, offering high security due to its memory overhead and configurability.
The choice between them depends on the context of use: 
- for hashing passwords and protecting user information, Argon2 is the best choice, 
- for signing data and ensuring its integrity, SHA-256 is the best choice.

### Building

Using Makefile:  make rebuild, restart, run, etc

### Future plans

- [x] added reading keys from DER format, documentation
- [x] automatic keys rotation with redis key publishing
- [x] key length 2048-bit, make longer key 4096-bit
- [x] add redis-based user suspicious activity detection / block
- [x] add redis-based registration / login locking (maintenance mode)
- [x] add refresh token with db storage
- [x] re-reading config using SIGHUP signal
- [x] add httpOnly cookie for refresh token
- [x] add docker deployment
- [x] add logging system information
- [ ] uber zap logging
- [ ] sliding salt position
- [ ] gRPC other services integration
