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

/*
 * Pairing bootstrap keeps its ephemeral private signing material inside Rust.
 * Callers can retrieve only the public Android-compatible URI/SVG payload.
 */
#define ENIGMA_PAIRING_CLAIM_ERROR 0u
#define ENIGMA_PAIRING_CLAIM_PENDING 1u
#define ENIGMA_PAIRING_CLAIMED 2u
#define ENIGMA_PAIRING_CLAIM_ALREADY_USED 3u
#define ENIGMA_PAIRING_CLAIM_EXPIRED 4u
#define ENIGMA_PAIRING_CLAIM_MISSING 5u

bool enigma_core_pairing_start(EnigmaCoreHandle *handle);
bool enigma_core_pairing_publish(EnigmaCoreHandle *handle);
uint32_t enigma_core_pairing_claim(EnigmaCoreHandle *handle);
bool enigma_core_device_session_ready(const EnigmaCoreHandle *handle);
bool enigma_core_device_initialize(EnigmaCoreHandle *handle);

/*
 * Desktop receive path. sync_pending performs relay fetch + libsignal decrypt +
 * crash-safe encrypted local commit before acknowledging delivery.
 */
bool enigma_core_sync_pending(EnigmaCoreHandle *handle);
size_t enigma_core_inbox_count(const EnigmaCoreHandle *handle);
size_t enigma_core_inbox_entry_json_len(
    const EnigmaCoreHandle *handle,
    size_t index);
bool enigma_core_inbox_entry_json_copy(
    const EnigmaCoreHandle *handle,
    size_t index,
    uint8_t *output,
    size_t output_len);

void enigma_core_pairing_cancel(EnigmaCoreHandle *handle);
size_t enigma_core_pairing_uri_len(const EnigmaCoreHandle *handle);
bool enigma_core_pairing_uri_copy(
    const EnigmaCoreHandle *handle,
    uint8_t *output,
    size_t output_len);
size_t enigma_core_pairing_svg_len(const EnigmaCoreHandle *handle);
bool enigma_core_pairing_svg_copy(
    const EnigmaCoreHandle *handle,
    uint8_t *output,
    size_t output_len);
uint64_t enigma_core_pairing_expires_at_unix_ms(const EnigmaCoreHandle *handle);

#ifdef __cplusplus
}
#endif
#endif
