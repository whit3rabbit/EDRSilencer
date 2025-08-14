#ifndef CORE_H
#define CORE_H

#include "utils.h"

void Initialize(void);
void configureNetworkFilters();
void addProcessRule(const char* processPath);
void removeAllRules();
void removeRuleById(UINT64 ruleId);
UINT64 CustomStrToULL(const char* str, char** endptr);

#endif
