#ifndef ENIGMA_CORE_H
#define ENIGMA_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EnigmaCoreHandle EnigmaCoreHandle;
#define ENIGMA_CORE_ABI_VERSION 1u

uint32_t enigma_core_abi_version(void);
EnigmaCoreHandle *enigma_core_create(void);
void enigma_core_destroy(EnigmaCoreHandle *handle);
bool enigma_core_is_ready(EnigmaCoreHandle *handle);

/*
 * Signal readiness is intentionally separate from basic runtime readiness.
 * A newly-created core is not E2EE-ready until a canonical libsignal identity
 * has been restored from platform-protected local storage.
 */
bool enigma_core_signal_is_ready(const EnigmaCoreHandle *handle);
bool enigma_core_signal_load_or_create_default(EnigmaCoreHandle *handle);
bool enigma_core_signal_initialize_protected(
    EnigmaCoreHandle *handle,
    const uint8_t *protected_identity,
    size_t protected_identity_len,
    uint32_t registration_id);

#ifdef __cplusplus
}
#endif
#endif
