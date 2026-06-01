# cipherusername-gen

lightweight, zero-dependency Go CLI utility designed to blind usernames for online identities

## Mechanism

- **Adaptive Stream Cipher Design (AES-CTR with random nonce)**: Automatically detects and adapts to the injected key length, supporting **AES-128-CTR**, **AES-192-CTR**, and **AES-256-CTR**
- **Decoupled Key Management**
- **Anti-Replay Defense**: Utilizes `crypto/rand` to inject a unique 16-byte nonce header into every encryption cycle, blocking statistical correlation attacks

## Getting Started
### 1. Prerequisites
Ensure Go toolchain is installed
```text
go version
```

### 2. Run
inject 16, 24, or 32-byte secret key via environment variables directly into your command session memory space, then execute according to platform:
- Linux / macOS: 
    - option A: run directly via memory injection
    ```
    ENCRYPTION_KEY="the-32-byte-secret-key-e.g.-here" go run main.go
    ```
    - option B: build native binary
    ```
    go build -o cipherusername-gen main.go
    ENCRYPTION_KEY="the-32-byte-secret-key-e.g.-here" ./cipherusername-gen
    ```

- Windows:
    - powershell session injection
    ```powershell
    $env:ENCRYPTION_KEY="the-32-byte-secret-key-e.g.-here"
    go run main.go
    ```

    - or build native executable
    ```powershell
    go build -o cipherusername-gen.exe main.go
    $env:ENCRYPTION_KEY="the-32-byte-secret-key-e.g.-here"; .\cipherusername-gen.exe
    ```
## License
MIT License.