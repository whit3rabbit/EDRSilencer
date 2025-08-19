#pragma once

#include "utils.hpp"
#include <netfw.h> // For Windows Firewall COM interfaces
#include <string>
#include <string_view>

namespace EDRSilencer
{
    // The group name starts with @ to hide it from the control panel UI
    #ifndef FIREWALL_RULE_GROUP
    #define FIREWALL_RULE_GROUP L"@EDRSilencer Rules"
    #endif

    // Public interface
    void FirewallConfigureBlockRules();
    void FirewallAddRuleByPath(std::string_view processPath);
    void FirewallRemoveRuleByPath(std::string_view processPath);
    void FirewallRemoveAllRules();
    void FirewallRemoveRuleByName(std::string_view ruleName);
}
