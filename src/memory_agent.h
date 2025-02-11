//
// Created by Jaewook Lee on 25. 2. 11.
//

#ifndef MEMORY_AGENT_H
#define MEMORY_AGENT_H
#include <string>
#include "agent.h"

namespace MemoryAgent {
    class MemoryAgent final : public Agent::IAgent {
    public:
        MemoryAgent();
        ~MemoryAgent() override;

        std::string Encrypt(const char *tableName, const char *columnName, const char *input) override;
        std::string Decrypt(const char *tableName, const char *columnName, const char *input) override;
        std::string Hash(const char *tableName, const char *columnName, const char *input) override;
    };
}

#endif //MEMORY_AGENT_H
