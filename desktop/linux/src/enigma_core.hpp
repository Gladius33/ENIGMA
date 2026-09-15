#pragma once

#include "../../include/enigma_core.h"

#include <cstdint>
#include <mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
    Core(Core&&) = delete;
    Core& operator=(Core&&) = delete;

    [[nodiscard]] bool ready() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr && enigma_core_is_ready(handle_);
    }

    [[nodiscard]] bool signalReady() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr && enigma_core_signal_is_ready(handle_);
    }

    [[nodiscard]] bool ensureDefaultSignalIdentity() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr && enigma_core_signal_load_or_create_default(handle_);
    }

    [[nodiscard]] bool initializeProtectedSignalIdentity(
        std::span<const std::uint8_t> protectedIdentity,
        std::uint32_t registrationId) noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && !protectedIdentity.empty()
            && enigma_core_signal_initialize_protected(
                handle_,
                protectedIdentity.data(),
                protectedIdentity.size(),
                registrationId);
    }

    [[nodiscard]] bool startPairing() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr || !enigma_core_pairing_start(handle_)) return false;
        if (!enigma_core_pairing_publish(handle_)) {
            enigma_core_pairing_cancel(handle_);
            return false;
        }
        return true;
    }

    [[nodiscard]] std::uint32_t claimPairing() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ == nullptr ? ENIGMA_PAIRING_CLAIM_ERROR : enigma_core_pairing_claim(handle_);
    }

    [[nodiscard]] bool deviceSessionReady() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr && enigma_core_device_session_ready(handle_);
    }

    [[nodiscard]] bool initializeDevice() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && signalReady()
            && deviceSessionReady()
            && enigma_core_device_initialize(handle_);
    }

    [[nodiscard]] bool syncPending() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && signalReady()
            && deviceSessionReady()
            && enigma_core_sync_pending(handle_);
    }

    [[nodiscard]] bool retryOutbox() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && signalReady()
            && deviceSessionReady()
            && enigma_core_retry_outbox(handle_);
    }

    [[nodiscard]] bool pollP2p() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && signalReady()
            && deviceSessionReady()
            && enigma_core_poll_p2p(handle_);
    }

    [[nodiscard]] bool sendText(
        const std::string& recipientUserId,
        const std::string& recipientPublicId,
        const std::string& recipientDisplayName,
        const std::string& bubbleId,
        const std::string& plaintext) noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr || !signalReady() || !deviceSessionReady()) return false;
        const EnigmaSendTextRequest request{
            reinterpret_cast<const std::uint8_t*>(recipientUserId.data()),
            recipientUserId.size(),
            reinterpret_cast<const std::uint8_t*>(recipientPublicId.data()),
            recipientPublicId.size(),
            reinterpret_cast<const std::uint8_t*>(recipientDisplayName.data()),
            recipientDisplayName.size(),
            reinterpret_cast<const std::uint8_t*>(bubbleId.data()),
            bubbleId.size(),
            reinterpret_cast<const std::uint8_t*>(plaintext.data()),
            plaintext.size(),
        };
        return enigma_core_send_text(handle_, &request);
    }

    [[nodiscard]] std::size_t outboxCount() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ == nullptr ? 0 : enigma_core_outbox_count(handle_);
    }

    [[nodiscard]] std::string contactsJson() {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr) return {};
        const auto length = enigma_core_contacts_json_len(handle_);
        if (length == 0) return "[]";
        std::vector<std::uint8_t> bytes(length);
        if (!enigma_core_contacts_json_copy(handle_, bytes.data(), bytes.size())) {
            return "[]";
        }
        return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    [[nodiscard]] bool sendTextToContact(
        const std::string& recipientUserId,
        const std::string& plaintext) noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ != nullptr
            && signalReady()
            && deviceSessionReady()
            && enigma_core_send_text_to_contact(
                handle_,
                reinterpret_cast<const std::uint8_t*>(recipientUserId.data()),
                recipientUserId.size(),
                reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                plaintext.size());
    }

    [[nodiscard]] std::size_t inboxCount() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ == nullptr ? 0 : enigma_core_inbox_count(handle_);
    }

    [[nodiscard]] std::string inboxEntryJson(std::size_t index) const {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr) return {};
        const auto length = enigma_core_inbox_entry_json_len(handle_, index);
        if (length == 0) return {};
        std::vector<std::uint8_t> bytes(length);
        if (!enigma_core_inbox_entry_json_copy(
                handle_, index, bytes.data(), bytes.size())) {
            return {};
        }
        return std::string(
            reinterpret_cast<const char*>(bytes.data()),
            bytes.size());
    }

    void cancelPairing() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ != nullptr) {
            enigma_core_pairing_cancel(handle_);
        }
    }

    [[nodiscard]] std::string pairingUri() const {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr) return {};
        const auto length = enigma_core_pairing_uri_len(handle_);
        if (length == 0) return {};
        std::vector<std::uint8_t> bytes(length);
        if (!enigma_core_pairing_uri_copy(handle_, bytes.data(), bytes.size())) return {};
        return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    [[nodiscard]] std::string pairingSvg() const {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ == nullptr) return {};
        const auto length = enigma_core_pairing_svg_len(handle_);
        if (length == 0) return {};
        std::vector<std::uint8_t> bytes(length);
        if (!enigma_core_pairing_svg_copy(handle_, bytes.data(), bytes.size())) return {};
        return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    [[nodiscard]] std::uint64_t pairingExpiresAtUnixMs() const noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        return handle_ == nullptr ? 0 : enigma_core_pairing_expires_at_unix_ms(handle_);
    }

private:
    void reset() noexcept {
        const std::lock_guard<std::recursive_mutex> lock(nativeMutex_);
        if (handle_ != nullptr) {
            enigma_core_destroy(handle_);
            handle_ = nullptr;
        }
    }

    mutable std::recursive_mutex nativeMutex_;
    EnigmaCoreHandle* handle_{nullptr};
};

} // namespace enigma
