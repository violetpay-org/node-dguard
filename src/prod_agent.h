//
// Created by Jaewook Lee on 25. 2. 11.
//

#ifndef PROD_AGENT_H
#define PROD_AGENT_H
#include <string>
#include "agent.h"

namespace ProdAgent {
    typedef int (*AgentFunc)(const char*, const char*, const char*, char*);

    class ProdAgent final : public Agent::IAgent {
    public:
        ProdAgent();
        ~ProdAgent() override;

        std::string Encrypt(const char *tableName, const char *columnName, const char *input) override;
        std::string Decrypt(const char *tableName, const char *columnName, const char *input) override;
        std::string Hash(const char *tableName, const char *columnName, const char *input) override;

    private:
        void* library = nullptr;
        AgentFunc dg_encrypt{};
        AgentFunc dg_decrypt{};
        AgentFunc dg_hash{};
        void loadFunction(AgentFunc *agentFunc, const char *name) const;
    };
}

#endif //PROD_AGENT_H
