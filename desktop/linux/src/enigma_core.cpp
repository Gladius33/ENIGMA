#include "enigma_core.hpp"

#include <cstdint>

namespace enigma {

static_assert(ENIGMA_CORE_ABI_VERSION == 1u, "Linux client expects ENIGMA Core ABI v1");

[[nodiscard]] std::uint32_t linked_core_abi_version() noexcept {
    return enigma_core_abi_version();
}

} // namespace enigma
