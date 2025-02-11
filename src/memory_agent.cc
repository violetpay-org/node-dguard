//
// Created by Jaewook Lee on 25. 2. 11.
//

#include "memory_agent.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <mutex>
#include <unordered_map>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <array>
#include <cstring>

// 내부에서만 사용할 헬퍼 함수와 전역 변수들
namespace {
    // (tableName, columnName)을 합쳐서 하나의 문자열 키로 생성
    std::string makeCompositeKey(const char* tableName, const char* columnName) {
        return std::string(tableName) + "|" + std::string(columnName);
    }

    // 바이너리 데이터를 16진수 문자열로 변환
    std::string bytesToHex(const unsigned char* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        return oss.str();
    }

    // Base64 인코딩: 바이너리 데이터를 base64 문자열로 변환
    std::string base64Encode(const unsigned char* data, size_t len) {
        int encodedSize = 4 * ((len + 2) / 3);
        std::vector<unsigned char> encoded(encodedSize + 1); // 널 종료 문자 공간 포함
        int actualSize = EVP_EncodeBlock(encoded.data(), data, len);
        return std::string(reinterpret_cast<char*>(encoded.data()), actualSize);
    }

    // Base64 디코딩: base64 문자열을 바이너리 데이터로 변환
    std::vector<unsigned char> base64Decode(const std::string& base64Str) {
        int length = static_cast<int>(base64Str.size());
        std::vector<unsigned char> decoded(3 * (length / 4) + 1); // 최대 크기
        int actualSize = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(base64Str.data()), length);
        if (actualSize < 0)
            throw std::runtime_error("Base64 decode 실패");

        // 입력 문자열에 있는 '=' 패딩 문자를 확인하여 실제 디코딩된 바이트 수를 조정
        int padding = 0;
        if (!base64Str.empty()) {
            if (base64Str[length - 1] == '=')
                padding++;
            if (length > 1 && base64Str[length - 2] == '=')
                padding++;
        }
        actualSize -= padding;
        decoded.resize(actualSize);
        return decoded;
    }

    // 16진수 문자열을 바이트 벡터로 변환
    std::vector<unsigned char> hexToBytes(const std::string& hex) {
        std::vector<unsigned char> bytes;
        if(hex.size() % 2 != 0)
            throw std::runtime_error("Invalid hex string length");
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned int byte;
            std::istringstream iss(hex.substr(i, 2));
            iss >> std::hex >> byte;
            bytes.push_back(static_cast<unsigned char>(byte));
        }
        return bytes;
    }

    // (tableName, columnName) -> 암호화 키 (32바이트 AES256 키)를 보관하는 맵과 이를 보호할 mutex
    std::unordered_map<std::string, std::array<unsigned char, 32>> keyMap;
    std::mutex keyMapMutex;
}

namespace MemoryAgent {
    MemoryAgent::MemoryAgent() = default;
    MemoryAgent::~MemoryAgent() = default;

    // Encrypt 함수: AES256-CBC를 사용하여 입력 문자열을 암호화한다.
    // 암호문에는 랜덤 IV(16바이트)가 선행되며, 최종 결과는 16진수 문자열로 반환된다.
    std::string MemoryAgent::Encrypt(const char *tableName, const char *columnName, const char *input) {
        // (tableName, columnName)이 합쳐진 키로 암호화 키 lookup
        std::string compositeKey = makeCompositeKey(tableName, columnName);
        std::array<unsigned char, 32> key;
        {
            std::lock_guard<std::mutex> lock(keyMapMutex);
            auto it = keyMap.find(compositeKey);
            if (it == keyMap.end()) {
                std::array<unsigned char, 32> newKey;
                if (RAND_bytes(newKey.data(), newKey.size()) != 1)
                    throw std::runtime_error("RAND_bytes for key failed");
                keyMap[compositeKey] = newKey;
                key = newKey;
            } else {
                key = it->second;
            }
        }

        // 랜덤 IV (16바이트) 생성
        unsigned char iv[16];
        if (RAND_bytes(iv, sizeof(iv)) != 1)
            throw std::runtime_error("RAND_bytes for IV failed");

        // EVP 암호문맥 생성
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        int inputLen = static_cast<int>(std::strlen(input));
        int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        std::vector<unsigned char> ciphertext(inputLen + blockSize);
        int outLen1 = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1, reinterpret_cast<const unsigned char*>(input), inputLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        int outLen2 = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        ciphertext.resize(outLen1 + outLen2);
        EVP_CIPHER_CTX_free(ctx);

        // IV를 암호문 앞에 붙임
        std::vector<unsigned char> output;
        output.insert(output.end(), iv, iv + sizeof(iv));
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());

        return base64Encode(output.data(), output.size());
    }

    // Decrypt 함수: 입력된 16진수 문자열(IV + 암호문)을 복호화하여 원본 문자열을 반환한다.
    std::string MemoryAgent::Decrypt(const char *tableName, const char *columnName, const char *input) {
        // 입력된 16진수 문자열을 바이트 배열로 변환
        std::vector<unsigned char> inData = base64Decode(std::string(input));
        if (inData.size() < 16)
            throw std::runtime_error("Input data too short for valid IV.");

        // IV 추출 및 암호문 분리
        unsigned char iv[16];
        std::copy(inData.begin(), inData.begin() + 16, iv);
        std::vector<unsigned char> ciphertext(inData.begin() + 16, inData.end());

        // 암호화 키 lookup
        std::string compositeKey = makeCompositeKey(tableName, columnName);
        std::array<unsigned char, 32> key;
        {
            std::lock_guard<std::mutex> lock(keyMapMutex);
            auto it = keyMap.find(compositeKey);
            if (it == keyMap.end()) {
                // 키가 없으면 새로 생성
                std::array<unsigned char, 32> newKey;
                if (RAND_bytes(newKey.data(), newKey.size()) != 1)
                    throw std::runtime_error("RAND_bytes for new key failed");
                keyMap[compositeKey] = newKey;
                key = newKey;
            } else {
                key = it->second;
            }
        }

        // EVP 복호문맥 생성
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        int ciphertextLen = static_cast<int>(ciphertext.size());
        int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        std::vector<unsigned char> plaintext(ciphertextLen + blockSize);
        int outLen1 = 0;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1, ciphertext.data(), ciphertextLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }
        int outLen2 = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptFinal_ex failed. Possibly wrong key or corrupted data.");
        }
        plaintext.resize(outLen1 + outLen2);
        EVP_CIPHER_CTX_free(ctx);

        return std::string(plaintext.begin(), plaintext.end());
    }

    // Hash 함수: HMAC-SHA256을 사용하여 입력 데이터에 대해 해시를 계산한다.
    // 암호화 키를 HMAC의 키로 사용하며 최종 결과는 16진수 문자열로 반환한다.
    std::string MemoryAgent::Hash(const char *tableName, const char *columnName, const char *input) {
        std::string compositeKey = makeCompositeKey(tableName, columnName);
        std::array<unsigned char, 32> key;
        {
            std::lock_guard<std::mutex> lock(keyMapMutex);
            auto it = keyMap.find(compositeKey);
            if (it == keyMap.end()) {
                std::array<unsigned char, 32> newKey;
                if (RAND_bytes(newKey.data(), newKey.size()) != 1)
                    throw std::runtime_error("RAND_bytes for new key failed");
                keyMap[compositeKey] = newKey;
                key = newKey;
            } else {
                key = it->second;
            }
        }

        unsigned char hashValue[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx)
            throw std::runtime_error("HMAC_CTX_new failed");

        if (HMAC_Init_ex(hctx, key.data(), key.size(), EVP_sha256(), nullptr) != 1) {
            HMAC_CTX_free(hctx);
            throw std::runtime_error("HMAC_Init_ex failed");
        }
        if (HMAC_Update(hctx, reinterpret_cast<const unsigned char*>(input), std::strlen(input)) != 1) {
            HMAC_CTX_free(hctx);
            throw std::runtime_error("HMAC_Update failed");
        }
        if (HMAC_Final(hctx, hashValue, &hashLen) != 1) {
            HMAC_CTX_free(hctx);
            throw std::runtime_error("HMAC_Final failed");
        }
        HMAC_CTX_free(hctx);

        return base64Encode(hashValue, hashLen);
    }

} // namespace MemoryAgent
