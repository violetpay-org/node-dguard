//
// Created by Jaewook Lee on 25. 2. 11.
//
#include "prod_agent.h"
#include <cstring> // C 스타일 문자열 처리
#include <dlfcn.h> // Linux/MacOS용 (Windows에서는 <windows.h> 사용)
#include <mutex> // 쓰레드 안전성 확보
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>

const std::string AGENT_ENCRYPTION_ERROR = "DG_ENC_ERROR";
const std::string AGENT_DECRYPTION_ERROR = "DG_DEC_ERROR";
const std::string AGENT_HASH_ERROR = AGENT_ENCRYPTION_ERROR;

enum class AgentError {
    None,
    EncryptionError,
    DecryptionError,
    HashError
};

const std::unordered_map<std::string, AgentError> AgentErrors = {
    {AGENT_ENCRYPTION_ERROR, AgentError::EncryptionError},
    {AGENT_DECRYPTION_ERROR, AgentError::DecryptionError},
    {AGENT_HASH_ERROR, AgentError::HashError}, // HashError는 EncryptionError와 동일한 에러 메시지를 뱉음
};

namespace ProdAgent {
    ProdAgent::ProdAgent() {
        const char *lib_path_env = std::getenv("EAP_HOME");
        if (!lib_path_env || strlen(lib_path_env) == 0) {
            throw std::runtime_error("EAP_HOME is not set");
        }

        const std::string lib_path = lib_path_env + std::string("/lib/libDGuardAPI.so");

        library = dlopen(lib_path.c_str(), RTLD_LAZY);
        if (!library) {
            const char *error = dlerror();
            throw std::runtime_error(std::string("Failed to load library: ") + (error ? error : "Unknown error"));
        }

        loadFunction(&dg_encrypt, "dg_encrypt");
        loadFunction(&dg_decrypt, "dg_decrypt");
        loadFunction(&dg_hash, "dg_hash");
    }

    void ProdAgent::loadFunction(AgentFunc *agentFunc, const char *name) const {
        *agentFunc = (AgentFunc)(dlsym(library, name));

        const char *error = dlerror();
        if (error != nullptr) {
            throw std::runtime_error(std::string("Failed to load function: ") + error);
        }
    }

    ProdAgent::~ProdAgent() {
        if (library) {
            dlclose(library);
            library = nullptr;
        }
    }

    std::string ProdAgent::Encrypt(const char *tableName, const char *columnName, const char *input) {
        const auto it = AgentErrors.find(std::string(input));
        if (it != AgentErrors.end()) {
            throw std::runtime_error("Encrypt error, You must not use reserved error string as input: " + std::string(input));
        }

        std::vector<char> result(5000);

        dg_encrypt(tableName, columnName, input, result.data());

        if (result.data() == AGENT_ENCRYPTION_ERROR) {
            throw std::runtime_error("Encrypt error, tableName: " + std::string(tableName) + ", columnName: " + std::string(columnName) + ", input: " + std::string(input));
        }

        return {result.data()};
    }

    std::string ProdAgent::Decrypt(const char *tableName, const char *columnName, const char *input) {
        const auto it = AgentErrors.find(std::string(input));
        if (it != AgentErrors.end()) {
            throw std::runtime_error("Decrypt error, You must not use reserved error string as input: " + std::string(input));
        }

        std::vector<char> result(5000);

        dg_decrypt(tableName, columnName, input, result.data());

        if (result.data() == AGENT_DECRYPTION_ERROR) {
            throw std::runtime_error("Decrypt error, tableName: " + std::string(tableName) + ", columnName: " + std::string(columnName) + ", input: " + std::string(input));
        }

        return {result.data()};
    }

    std::string ProdAgent::Hash(const char *tableName, const char *columnName, const char *input) {
        const auto it = AgentErrors.find(std::string(input));
        if (it != AgentErrors.end()) {
            throw std::runtime_error("Hash error, You must not use reserved error string as input: " + std::string(input));
        }

        std::vector<char> result(5000);

        dg_hash(tableName, columnName, input, result.data());

        if (result.data() == AGENT_HASH_ERROR) {
            throw std::runtime_error("Hash error, tableName: " + std::string(tableName) + ", columnName: " + std::string(columnName) + ", input: " + std::string(input));
        }

        return {result.data()};
    }
}