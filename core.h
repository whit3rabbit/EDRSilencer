#ifndef CORE_H
#define CORE_H


#include "utils.h"

// Global flags from main.c
extern BOOL g_isForce;

/*
 * core.h
 * ------
 * Public interface for the WFP-based functionality of EDRSilencer.
 *
 * Design/Rationale (see core.c for details):
 * - Filters are installed under our own provider and a dedicated sublayer.
 * - Sublayer weight is set to the maximum value so our sublayer wins arbitration vs others.
 * - Individual filters use the maximum 64-bit weight so they dominate within our sublayer.
 * - Provider/sublayer/filter names are overrideable via macros in utils.h for OPSEC.
 */

// Manually define WFP flags if missing from toolchain headers (e.g., some MinGW variants)
#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#endif

#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#endif

#ifndef EDR_PROVIDER_DESCRIPTION
#define EDR_PROVIDER_DESCRIPTION L"Provider for EDR Silencer to manage network filters."
#endif

#ifndef EDR_SUBLAYER_DESCRIPTION
#define EDR_SUBLAYER_DESCRIPTION L"Sublayer for EDR Silencer to ensure filter precedence."
#endif

// High-level operations (implemented in core.c)
// configureNetworkFilters: Bulk apply generic block filters for known EDR processes.
void configureNetworkFilters();
// addProcessRule: Apply generic block filters for a single process path.
void addProcessRule(const char* processPath);
// removeAllRules: Remove all filters owned by our provider and tear down sublayer/provider.
void removeAllRules(BOOL isForce);
// removeRuleById: Delete a single filter by its numeric ID (see listRules to discover IDs).
void removeRuleById(UINT64 ruleId);
// removeRulesByPath: Convert path -> AppID and remove all matching filters across key layers.
void removeRulesByPath(const char* processPath);
// listRules: Enumerate filters owned by our provider (IDs and display names).
void listRules();
// Utility: robust numeric conversion used by exports/BOF for ID parsing.
UINT64 CustomStrToULL(const char* str, char** endptr);

#endif
