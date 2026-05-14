#pragma once

#include <string>
#include <vector>
#include <memory>

// Forward declarations for YARA structs to avoid including yara.h here
struct YR_COMPILER;
struct YR_RULES;

namespace antivirus::agent {

struct YaraMatch {
    std::string ruleName;
    std::string namespaceName;
    std::vector<std::string> tags;
};

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();

    bool Initialize();
    bool LoadRule(const std::string& ruleString, std::string& errorMsg);
    
    bool ScanFile(const std::wstring& filePath, std::vector<YaraMatch>& matches);
    bool ScanMemory(const uint8_t* buffer, size_t size, std::vector<YaraMatch>& matches);

private:
    YR_COMPILER* compiler_ = nullptr;
    YR_RULES* rules_ = nullptr;
    bool initialized_ = false;
};

} // namespace antivirus::agent
