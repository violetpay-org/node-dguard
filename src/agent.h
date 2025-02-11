//
// Created by Jaewook Lee on 25. 1. 17.
//

#ifndef AGENT_H
#define AGENT_H
#include <string>

namespace Agent {
    void Init(bool isLocal);
    std::string Encrypt(const char *tableName, const char *columnName, const char *input);
    std::string Decrypt(const char *tableName, const char *columnName, const char *input);
    std::string Hash(const char *tableName, const char *columnName, const char *input);
    void Close();

    class IAgent {
    public:
        IAgent() = default;
        virtual ~IAgent() = default;
        virtual std::string Encrypt(const char *tableName, const char *columnName, const char *input) = 0;
        virtual std::string Decrypt(const char *tableName, const char *columnName, const char *input) = 0;
        virtual std::string Hash(const char *tableName, const char *columnName, const char *input) = 0;
    };
}

#endif //AGENT_H
