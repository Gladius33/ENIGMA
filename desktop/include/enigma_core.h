#ifndef ENIGMA_CORE_H
#define ENIGMA_CORE_H

#include <stdbool.h>
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

#ifdef __cplusplus
}
#endif
#endif
