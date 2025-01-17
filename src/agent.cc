#include "agent.h"
#include <cstring> // C 스타일 문자열 처리
#include <dlfcn.h> // Linux/MacOS용 (Windows에서는 <windows.h> 사용)
#include <mutex> // 쓰레드 안전성 확보
#include <string>
#include <vector>

namespace Agent {
    void *library = nullptr;
    std::mutex library_mutex;

    typedef char* (*AgentFunc)(const char*, const char*, const char*, char*);
    AgentFunc dg_encrypt = nullptr;
    AgentFunc dg_decrypt = nullptr;
    AgentFunc dg_hash = nullptr;

    void loadFunction(AgentFunc *agentFunc, const char *name) {
        *agentFunc = (AgentFunc)(dlsym(library, name));

        const char *error = dlerror();
        if (error != nullptr) {
            throw std::runtime_error(std::string("Failed to load function: ") + error);
        }
    }

    void Init() {
        std::lock_guard<std::mutex> lock(library_mutex);
        if (library == nullptr) {
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
    }

    void Close() {
        std::lock_guard<std::mutex> lock(library_mutex);
        if (library) {
            dlclose(library);
            library = nullptr;
        }
    }

    std::string Encrypt(const char *tableName, const char *columnName, const char *input) {
        std::vector<char> result(5000);

        dg_encrypt(tableName, columnName, input, result.data());

        return {result.data()};
    }

    std::string Decrypt(const char *tableName, const char *columnName, const char *input) {
        std::vector<char> result(5000);

        dg_decrypt(tableName, columnName, input, result.data());

        return {result.data()};
    }

    std::string Hash(const char *tableName, const char *columnName, const char *input) {
        std::vector<char> result(5000);

        dg_hash(tableName, columnName, input, result.data());

        return {result.data()};
    }
}