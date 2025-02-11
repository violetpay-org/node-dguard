#include "agent.h"
#include <string>
#include "prod_agent.h"
#include "memory_agent.h"
#include <atomic>
#include <stdexcept>

namespace Agent {
    std::atomic<bool> initializedFlag;
    IAgent *agent = nullptr;

    void Init(const bool isLocal) {
        if (isLocal) {
            agent = new MemoryAgent::MemoryAgent();
        } else {
            agent = new ProdAgent::ProdAgent();
        }

        initializedFlag.store(true);
    }

    std::string Encrypt(const char *tableName, const char *columnName, const char *input) {
        if (!initializedFlag.load()) {
            throw std::runtime_error("Agent is not initialized");
        }

        return agent->Encrypt(tableName, columnName, input);
    }

    std::string Decrypt(const char *tableName, const char *columnName, const char *input) {
        if (!initializedFlag.load()) {
            throw std::runtime_error("Agent is not initialized");
        }

        return agent->Decrypt(tableName, columnName, input);
    }


    std::string Hash(const char *tableName, const char *columnName, const char *input) {
        if (!initializedFlag.load()) {
            throw std::runtime_error("Agent is not initialized");
        }

        return agent->Hash(tableName, columnName, input);
    }

    void Close() {
        delete agent;

        initializedFlag.store(false);
    }
}