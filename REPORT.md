# T27 DeathNode Project Report

## 1. Introduction

DeathNode is an anonymous reporting platform used by a peer-based network run by a group called The Cult of Kika. The system allows members to submit reports about alleged crimes or suspects before this information reaches the authorities. Because the reports can include sensitive information, protecting the identity of users was a major concern from the start. For this reason, users do not use real names and instead interact with the system using pseudonyms.

Each user runs their own node, which stores reports locally in encrypted form. These reports are shared with other nodes through periodic synchronization. Using a peer-to-peer approach makes the system more resilient, but it also creates some problems. Nodes cannot simply trust each other, so they must be able to detect if a report was changed, deleted, duplicated, or received in the wrong order.

To prevent these issues, reports are protected using cryptographic mechanisms. Encryption ensures that only authorized nodes can read the content, and integrity checks allow nodes to detect any changes. Although the system was originally fully decentralized, an extra requirement was later added to control who can join the network. For that reason, a central authorization server was introduced to approve new participants and issue time-limited credentials, while still keeping users anonymous.

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

The secure document format provides confidentiality, integrity, and authenticity for crime reports while maintaining user anonymity through pseudonyms.

**Cryptographic Algorithms:**
- **AES-256-GCM**: Encryption with built-in integrity protection
- **SHA256withRSA**: Digital signatures for authenticity
- **JSON format**: Structured data representation
- **Base64 encoding**: Safe binary data transport

**Secure Document Structure:**
```json
{
  "algorithm": "AES-256-GCM",
  "signature_algorithm": "SHA256withRSA",
  "iv": "Base64EncodedInitializationVector",
  "encrypted_data": "Base64EncodedCiphertextWithAuthenticationTag",
  "signature": "Base64EncodedRSASignature",
  "signer_id": "alice_pseudonym",
  "timestamp": "2024-12-20T10:30:00Z",
  "sequence_number": 42,
  "previous_hash": "SHA256HashOfPreviousDocument"
}
```

**Security Functions:**
- **Confidentiality**: AES-256-GCM encrypts report content
- **Integrity**: GCM authentication tag detects modifications
- **Authenticity**: RSA signatures verify report origin
- **Chain Integrity**: Sequence numbers and hash chaining prevent tampering

#### 2.1.2. Implementation

**Technology Stack:**
- **Java 17**: Programming language
- **Java Cryptography Extension (JCE)**: Cryptographic operations
- **Gson**: JSON serialization
- **SQLite**: Local data storage

**Core Classes:**

**CryptoLib Class** (`src/main/java/pt/DeathNode/crypto/CryptoLib.java`)
- `protect(Report, SecretKey, PrivateKey, String)`: Encrypts and signs reports
- `protect(Report, SecretKey, PrivateKey, String, Long, String)`: Encrypts with sequence/hash
- `check(SecureDocument, PublicKey)`: Verifies signatures
- `unprotect(SecureDocument, SecretKey, PublicKey)`: Decrypts reports

**Cryptographic Constants (Verified):**
- `AES_GCM = "AES/GCM/NoPadding"`
- `SIGNATURE_ALGORITHM = "SHA256withRSA"`
- `GCM_IV_LENGTH = 12` bytes
- `GCM_TAG_LENGTH = 128` bits

**KeyManager Class** (`src/main/java/pt/DeathNode/crypto/KeyManager.java`)
- `generateSymmetricKey()`: AES-256 key generation (`AES_KEY_SIZE = 256`)
- `generateKeyPair()`: RSA-2048 key pair generation (`RSA_KEY_SIZE = 2048`)
- `saveSymmetricKey(SecretKey, String)`: Key persistence to `keys/` directory
- `loadSymmetricKey(String)`: Key retrieval from `keys/` directory

**SecureDocument Class** (`src/main/java/pt/DeathNode/crypto/SecureDocument.java`)
- JSON structure with `@SerializedName` annotations
- Format identifier: `"DeathNode-Secure-v1"`
- Fields: `algorithm`, `signature_algorithm`, `iv`, `encrypted_data`, `signature`, `signer_id`, `timestamp`, `sequence_number`, `previous_hash`
- Uses Gson for JSON serialization/deserialization

**Report Class** (`src/main/java/pt/DeathNode/crypto/Report.java`)
- JSON structure with `@SerializedName` annotations
- Fields: `report_id`, `timestamp`, `reporter_pseudonym`, `content`, `version`, `status`
- Uses UUID for report ID generation
- Contains nested `ReportContent` class for actual report data
- Matches original project specification format exactly

**ReportContent Class** (`src/main/java/pt/DeathNode/crypto/ReportContent.java`)
- JSON structure with `@SerializedName` annotations
- Fields: `suspect`, `description`, `location`
- Constructor: `ReportContent(String suspect, String description, String location)`
- Matches project specification example content exactly

**Implementation Issues Resolved:**
- GCM parameter specification (12-byte IV, 128-bit tag)
- Base64 encoding for JSON compatibility
- RSA key size selection (2048 bits)
- Exception handling for cryptographic operations

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

**Network Configuration:**
- **DMZ Network (10.0.1.0/24)**: Authentication Server isolation
- **Internal Network (10.0.2.0/24)**: Client-Gateway communication
- **NAT Interface**: Internet access through Gateway

**Virtual Machine Specifications:**

**Authentication Server (auth)**
- IP: 10.0.1.20/24 (eth0)
- Single network interface
- No internet connectivity
- Service: HTTPS on port 8080 (default)
- Database: SQLite (`db/deathnode.db`)

**Gateway/Server API (deathnode-gateway)**
- eth0: 10.0.1.10/24 (DMZ - Auth access)
- eth1: 10.0.2.10/24 (Internal - Client access)
- eth2: DHCP (NAT - Internet)
- Service: HTTPS on port 9090 (default)
- Database: SQLite (`db/deathnode.db`)

**Client Nodes**
- alice: 10.0.2.12/24
- bob: 10.0.2.11/24
- kira: 10.0.2.13/24
- Gateway: 10.0.2.10
- Terminal UI clients

**Technology Choices:**
- **VirtualBox**: Virtualization platform
- **Linux Kali**: Base operating system
- **iptables**: Network security enforcement
- **SQLite**: Local database storage

**Network Security Rules:**
- Client-to-client communication: BLOCKED
- Client-to-Auth direct access: BLOCKED
- Gateway-to-Auth: ALLOWED (HTTPS only)
- Client-to-Gateway: ALLOWED (HTTPS only)

#### 2.2.2. Server Communication Security

**TLS Implementation:**
- **Protocol**: TLS 1.3 with TLS 1.2 fallback
- **Certificate Format**: PKCS12 keystores
- **Authentication**: Mutual certificate validation
- **Cipher Suites**: Strong encryption prioritized

**Certificate Authority Setup:**
- **Root CA**: `certs/ca/ca.p12` (self-generated)
- **Server Certificates**:
  - Auth Server: `certs/auth/auth.p12`
  - Gateway: `certs/gateway/gateway.p12`
  - Alice: `certs/alice/alice.p12`
  - Bob: `certs/bob/bob.p12`
  - Kira: `certs/kira/kira.p12`

**Certificate Generation Process:**
1. CA creation via `setup_scripts/ca-generate.sh`
2. Individual certificates for each VM
3. Distribution through shared folders
4. Installation in `certs/` directories

**TLS Configuration:**
- **Truststores**: CA certificate in each VM
- **Environment Variables**:
  - `DEATHNODE_TLS_KEYSTORE_PATH`
  - `DEATHNODE_TLS_KEYSTORE_PASSWORD`

**Communication Security:**
- **Client → Gateway**: TLS with client certificates
- **Gateway → Auth**: TLS mutual authentication
- **All Traffic**: End-to-end encryption
- **Certificate Validation**: Prevents MITM attacks

**Implementation Issues Resolved:**
- Certificate management across 5 VMs
- Offline certificate distribution via shared folders
- TLS handshake consistency across Java versions
- Certificate trust chain validation

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

**Security Challenge A Requirements:**
- Invitation-based network enrollment
- Centralized authorization server
- Time-limited access credentials
- Anonymous participation
- Secure negotiated sessions

**Architecture Changes:**
- Added Authentication Server (blind-auth)
- Modified network topology to star configuration
- Enhanced TLS certificate management
- Extended database schema for tokens and users

**Protocol Modifications:**
- Multi-step enrollment workflow
- Token validation process
- Public key exchange during enrollment
- Gateway authentication against Auth Server

#### 2.3.2. Attacker Model

**Trust Levels:**
- **Fully Trusted**: Auth Server, CA, infrastructure
- **Partially Trusted**: Gateway, privileged users (Alice, Bob)
- **Untrusted**: New users, external networks

**Attacker Capabilities:**
- **External Network**: Traffic monitoring, interception attempts
- **Malicious Client**: Valid certificates, unauthorized access attempts
- **Token Forger**: Guessing tokens, replay attacks
- **MITM**: TLS handshake interception
- **DoS**: Service flooding, resource exhaustion

**Attacker Limitations:**
- TLS encryption prevents traffic decryption
- Network isolation blocks direct client access
- Cryptographic random tokens prevent forgery
- Certificate validation prevents impersonation

#### 2.3.3. Solution Design and Implementation

**Authentication Server Components:**
- **AuthServerMain Class** (`src/main/java/pt/DeathNode/auth/AuthServerMain.java`): Main server implementation
- **Token Management Service**: Creates, validates, and manages invitation tokens
- **User Enrollment Service**: Handles new user registration and credential issuance
- **SQLite database** (`db/deathnode.db`): Persistent token and user storage
- **HTTPS API endpoint**: Port 8080 (default) for secure client communication

**Gateway Server Components:**
- **ApplicationServer Class** (`src/main/java/pt/DeathNode/server/ApplicationServer.java`): Main server implementation
- **Client Authentication**: Validates user credentials against Auth Server
- **Report Mediation**: Forwards reports between clients while maintaining security
- **SQLite database** (`db/deathnode.db`): Local report storage
- **HTTPS API endpoint**: Port 9090 (default) for client access

**Invitation Token System:**
- **InvitationToken Class** (`src/main/java/pt/DeathNode/auth/InvitationToken.java`): Token implementation
- **Format**: 128-bit cryptographically random (16 bytes, URL-safe Base64 without padding)
- **Fields**: `tokenId`, `issuerId`, `issuedAt`, `expiresAt`, `maxUses`, `currentUses`, `active`, `description`
- **Creation**: `create(String issuerId, int maxUses, long validityHours, String description)`
- **Validation**: Server-side database verification via `isValid()` method
- **Consumption**: Single-use token marking (increments `currentUses`)

**Key Distribution:**
- Public key exchange during enrollment
- Certificate binding to pseudonyms
- Session key derivation
- Key rotation mechanisms

**Communication Flow:**

**Enrollment Sequence:**
1. Alice creates token via Auth Server API
2. Alice shares token with Kira (out-of-band)
3. Kira submits join request with token
4. Auth Server validates token
5. Public key exchange between Kira and Auth Server
6. Enrollment completion

**Report Submission:**
1. Client submits encrypted report to Gateway
2. Gateway validates user with Auth Server
3. Gateway stores report locally
4. Gateway confirms receipt to client

**Security Measures:**
- Token security (random generation, expiration, limits)
- Network security (TLS, iptables, certificates)
- Data protection (AES-256-GCM, RSA signatures, hash chaining)
- Access control (role-based permissions, invitation enrollment)  

## 3. Conclusion

In this project, we designed DeathNode, an anonymous peer-based reporting system that allows users to share crime related information without revealing their identity. The main focus was making sure reports could be stored and shared securely between nodes, even though the system does not fully trust its participants.

All the security requirements were met. Reports are encrypted so only authorized nodes can read them, and integrity checks make it possible to detect any changes. During synchronization, nodes can also detect missing, duplicated, or out-of-order reports. Adding a central authorization server helped control who can join the network, while still keeping users anonymous.

There are still some things that could be improved, like handling expired or compromised credentials more smoothly or making synchronization work better on bigger networks. Overall, this project helped us see how anonymity and security can be combined in a distributed system and gave us practical experience dealing with real-world design challenges.

## 4. Bibliography

Segurança em redes informáticas: André Zúquete 2018 5ª edição, FCA. ISBN: 9789727228577
Network Security Essentials: Applications and Standards,: William Stallings 2017 6th Edition, Pearson. ISBN: 978-0134527338
Security Engineering: A Guide to Building Dependable Distributed Systems: Ross Anderson 2020 3rd Edition, ISBN: 978-1-119-64281-7

----