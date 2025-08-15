#ifndef CORE_H
#define CORE_H


#include "utils.h"

// Manually define WFP flags if they are not available in the MinGW headers
#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#endif

#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#endif

#define EDR_PROVIDER_DESCRIPTION L"Provider for EDR Silencer to manage network filters."
#define EDR_SUBLAYER_DESCRIPTION L"Sublayer for EDR Silencer to ensure filter precedence."

void configureNetworkFilters();
void addProcessRule(const char* processPath);
void removeAllRules();
void removeRuleById(UINT64 ruleId);
void removeRulesByPath(const char* processPath);
UINT64 CustomStrToULL(const char* str, char** endptr);

#endif
