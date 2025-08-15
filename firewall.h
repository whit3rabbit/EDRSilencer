#ifndef FIREWALL_H
#define FIREWALL_H

#include "utils.h"
#include <netfw.h> // For Windows Firewall COM interfaces

// The group name starts with @ to hide it from the control panel UI
#define FIREWALL_RULE_GROUP L"@EDRSilencer Rules"

// Public interface
void FirewallConfigureBlockRules();
void FirewallAddRuleByPath(const char* processPath);
void FirewallRemoveRuleByPath(const char* processPath);
void FirewallRemoveAllRules();
void FirewallRemoveRuleByName(const char* ruleName);

#endif // FIREWALL_H
