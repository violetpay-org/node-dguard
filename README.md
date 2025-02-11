# DGuard

## Installation

### 1. Install Clang, OpenSSL

* CentOS, Fedora, RHEL
```bash
sudo yum install openssl-devel
```

* Ubuntu
```bash
sudo apt-get install libssl-dev
```

* macOS
```bash
xcode-select --install 
```

If you have a problem although your mac already installed xcode-select, you can try this command (not responsible for any damage):
```bash
sudo rm -rf /Library/Developer/CommandLineTools
xcode-select --install
```

### 2. Install the package

```bash
npm i dguard
```

## Usage

```typescript
dguard.init({ local: false });

async function myFunction() {
      const encrypted = await dguard.encrypt("CRYPTO", "ENC", "테스트");
      console.log("ENC:", encrypted); // "ENC: KrYf33BmD8uoqlWEQ8AG9A=="
      const decrypted = await dguard.decrypt("CRYPTO", "ENC", encrypted);
      console.log("DEC:", decrypted); // "DEC: 테스트"
      const hashed = await dguard.hash("CRYPTO", "PWD", "1111111111");
      console.log("PWD:", hashed); // "PWD: R4RJJu0F8cTeWYH3o5GqNriPQdjcX0UpmoZGrqBJq2s="
}

dguard.close();
```
