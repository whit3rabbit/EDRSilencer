#pragma once

#include "utils.hpp"
#include <string>
#include <string_view>

namespace EDRSilencer
{
    /*
     * core.hpp
     * ------
     * Public interface for the WFP-based functionality of EDRSilencer.
     *
     * Design/Rationale (see core.cpp for details):
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

    // High-level operations (implemented in core.cpp)
    void configureNetworkFilters();
    void addProcessRule(std::string_view processPath);
    void removeAllRules(BOOL isForce);
    void removeRuleById(UINT64 ruleId);
    void removeRulesByPath(std::string_view processPath);
    void listRules();
    UINT64 CustomStrToULL(const char* str, char** endptr);
}
