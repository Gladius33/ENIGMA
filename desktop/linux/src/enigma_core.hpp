#pragma once

#include "../../include/enigma_core.h"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>

namespace enigma {

[[nodiscard]] std::uint32_t linked_core_abi_version() noexcept;

class Core final {
public:
    Core() : handle_(enigma_core_create()) {
        if (handle_ == nullptr) throw std::runtime_error("Unable to create ENIGMA core");
        if (enigma_core_abi_version() != ENIGMA_CORE_ABI_VERSION) {
            enigma_core_destroy(handle_);
            handle_ = nullptr;
            throw std::runtime_error("Unsupported ENIGMA core ABI");
        }
    }

    ~Core() { reset(); }

    Core(const Core&) = delete;
    Core& operator=(const Core&) = delete;
    Core(Core&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    Core& operator=(Core&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] bool ready() const noexcept {
        return handle_ != nullptr && enigma_core_is_ready(handle_);
    }

    [[nodiscard]] bool signalReady() const noexcept {
        return handle_ != nullptr && enigma_core_signal_is_ready(handle_);
    }

    [[nodiscard]] bool ensureDefaultSignalIdentity() noexcept {
        return handle_ != nullptr && enigma_core_signal_load_or_create_default(handle_);
    }

    [[nodiscard]] bool initializeProtectedSignalIdentity(
        std::span<const std::uint8_t> protectedIdentity,
        std::uint32_t registrationId) noexcept {
        return handle_ != nullptr
            && !protectedIdentity.empty()
            && enigma_core_signal_initialize_protected(
                handle_,
                protectedIdentity.data(),
                protectedIdentity.size(),
                registrationId);
    }

private:
    void reset() noexcept {
        if (handle_ != nullptr) {
            enigma_core_destroy(handle_);
            handle_ = nullptr;
        }
    }

    EnigmaCoreHandle* handle_{nullptr};
};

} // namespace enigma
