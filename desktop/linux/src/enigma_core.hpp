#pragma once

#include "../../include/enigma_core.h"

#include <stdexcept>
#include <utility>

namespace enigma {

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
