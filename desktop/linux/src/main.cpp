#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDialog>
#include <QFont>
#include <QFrame>
#include <QFutureWatcher>\n#include <QIcon>\n#include <QLocale>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPalette>
#include <QPixmap>
#include <QPushButton>\n#include <QSettings>
#include <QSvgWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QtConcurrent/QtConcurrentRun>

#include <exception>
#include <memory>

#include "../../design/enigma_tokens.hpp"
#include "enigma_core.hpp"

namespace {

enum class UiLanguage {
    French,
    English,
};

UiLanguage systemLanguage() {
    return QLocale::system().language() == QLocale::French
        ? UiLanguage::French
        : UiLanguage::English;
}

QString l10n(UiLanguage language, const char* fr, const char* en) {
    return QString::fromUtf8(language == UiLanguage::French ? fr : en);
}

bool isDarkPalette(const QPalette& palette) {
    return palette.color(QPalette::Window).lightness() < 128;
}

QString buildStyleSheet(bool dark) {
    using namespace enigma::design;
    const auto background = dark ? kBackgroundDark : kBackgroundLight;
    const auto surface = dark ? kSurfaceDark : kSurfaceLight;
    const auto primary = dark ? kPrimaryDark : kPrimary;
    const auto text = dark ? "#F7F8FA" : "#171B22";
    const auto muted = dark ? "#AEB6C2" : "#667085";
    const auto border = dark ? "#2A303A" : "#E4E7EC";

    return QStringLiteral(
               "QWidget#root { background: %1; color: %2; }"
               "QFrame#surface { background: %3; border: 1px solid %4; border-radius: %5px; }"
               "QLabel#brand { color: %2; font-size: 24px; font-weight: 700; }"
               "QLabel#headline { color: %2; font-size: 20px; font-weight: 700; }"
               "QLabel#body { color: %6; font-size: 14px; }"
               "QLabel#secure { color: %7; font-size: 13px; font-weight: 600; }"
               "QPushButton { background: %8; color: white; border: none; border-radius: 10px;"
               " padding: 10px 18px; font-size: 14px; font-weight: 600; }"
               "QPushButton:focus { outline: 2px solid %9; }"
               "QPushButton:disabled { background: %4; color: %6; }"
               "QComboBox, QLineEdit, QListWidget { background: %3; color: %2; border: 1px solid %4;"
               " border-radius: 10px; padding: 8px; font-size: 14px; }"
               "QComboBox:focus, QLineEdit:focus, QListWidget:focus { border: 2px solid %9; }"
               "QListWidget { padding: 6px; }")
        .arg(background)
        .arg(text)
        .arg(surface)
        .arg(border)
        .arg(kCornerRadius)
        .arg(muted)
        .arg(kEncrypted)
        .arg(primary)
        .arg(kSecondary);
}

}  // namespace

int main(int argc, char* argv[]) {
    // Bootstrap the Qt application identity before any widget or native-core work.
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("ENIGMA"));
    app.setOrganizationName(QStringLiteral("ENIGMA"));
    QSettings settings;
    const QString savedLanguage = settings.value(QStringLiteral("ui/language")).toString();
    UiLanguage language = savedLanguage == QStringLiteral("fr")
        ? UiLanguage::French
        : savedLanguage == QStringLiteral("en")
            ? UiLanguage::English
            : systemLanguage();

    // Initialize the Rust/libsignal core and derive the initial operational state fail-closed.
    std::unique_ptr<enigma::Core> core;
    bool coreReady = false;
    bool signalReadyForPairing = false;
    QString coreStatus = l10n(language, "Cœur sécurisé indisponible", "Secure core unavailable");
    QString coreDetail = l10n(language, "Le cœur Rust/libsignal n’est pas prêt", "The Rust/libsignal core is not ready");

    try {
        core = std::make_unique<enigma::Core>();
        const bool runtimeReady = core->ready();
        const bool signalReady = runtimeReady
            && (core->signalReady() || core->ensureDefaultSignalIdentity());
        signalReadyForPairing = signalReady;
        const bool sessionReady = signalReady && core->deviceSessionReady();
        const bool deviceReady = sessionReady && core->initializeDevice();
        coreReady = signalReady && sessionReady && deviceReady;
        const bool outboxFlushed = coreReady && core->retryOutbox();
        const bool inboxSynced = coreReady && core->syncPending();
        const std::size_t inboxCount = coreReady ? core->inboxCount() : 0;
        const std::size_t outboxCount = coreReady ? core->outboxCount() : 0;
        if (coreReady) {
            coreStatus = l10n(language, "Cœur sécurisé prêt • appareil lié", "Secure core ready • device linked");
            coreDetail = inboxSynced && outboxFlushed
                ? l10n(language, "Rust/libsignal • ABI %1 • %2 message(s) local(aux)", "Rust/libsignal • ABI %1 • %2 local message(s)")
                      .arg(enigma::linked_core_abi_version())
                      .arg(static_cast<qulonglong>(inboxCount))
                : l10n(language, "Rust/libsignal • ABI %1 • %2 livraison(s) en attente", "Rust/libsignal • ABI %1 • %2 pending delivery item(s)")
                      .arg(enigma::linked_core_abi_version())
                      .arg(static_cast<qulonglong>(outboxCount));
        } else if (signalReady && sessionReady) {
            coreStatus = l10n(language, "Session liée • initialisation réseau requise", "Linked session • network initialization required");
            coreDetail = QStringLiteral(
                "Session device restaurée, mais la publication des prekeys doit être réessayée");
        } else if (signalReady) {
            coreStatus = l10n(language, "Appairage Android requis", "Android pairing required");
            coreDetail = l10n(language, "Identité libsignal prête • liez cet ordinateur depuis Android", "Libsignal identity ready • link this computer from Android");
        } else if (runtimeReady) {
            coreStatus = l10n(language, "Identité E2EE protégée requise", "Protected E2EE identity required");
            coreDetail = l10n(language, "Rust chargé • ABI %1 • identité libsignal non restaurée", "Rust loaded • ABI %1 • libsignal identity not restored")
                             .arg(enigma::linked_core_abi_version());
        }
    } catch (const std::exception& error) {
        coreDetail = l10n(language, "Initialisation du cœur ENIGMA impossible : %1", "Unable to initialize the ENIGMA core: %1")
                         .arg(QString::fromUtf8(error.what()));
    }

    // Build the top-level desktop shell only after native-core initialization has been attempted.
    QWidget window;
    window.setObjectName(QStringLiteral("root"));
    window.setWindowTitle(QStringLiteral("ENIGMA"));
    window.setWindowIcon(QIcon(QStringLiteral(":/enigma/enigma_logo.png")));
    window.resize(920, 620);
    window.setMinimumSize(680, 460);
    const bool darkTheme = isDarkPalette(app.palette());
    window.setStyleSheet(buildStyleSheet(darkTheme));

    // Compose the persistent application chrome and spacing from shared ENIGMA design tokens.
    auto* root = new QVBoxLayout(&window);
    root->setContentsMargins(
        enigma::design::kSpacingXl,
        enigma::design::kSpacingXl,
        enigma::design::kSpacingXl,
        enigma::design::kSpacingXl);
    root->setSpacing(enigma::design::kSpacingLg);

    auto* header = new QHBoxLayout();
    header->setSpacing(enigma::design::kSpacingMd);

    auto* logo = new QLabel(&window);
    QPixmap logoPixmap(QStringLiteral(":/enigma/enigma_logo.png"));
    logo->setPixmap(logoPixmap.scaled(56, 56, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    logo->setFixedSize(56, 56);
    logo->setAccessibleName(QStringLiteral("ENIGMA"));

    auto* brand = new QLabel(QStringLiteral("ENIGMA"), &window);
    brand->setObjectName(QStringLiteral("brand"));
    brand->setAccessibleName(QStringLiteral("ENIGMA"));

    auto* languageSelector = new QComboBox(&window);
    languageSelector->addItem(QStringLiteral("Français"), static_cast<int>(UiLanguage::French));
    languageSelector->addItem(QStringLiteral("English"), static_cast<int>(UiLanguage::English));
    languageSelector->setCurrentIndex(language == UiLanguage::French ? 0 : 1);
    languageSelector->setAccessibleName(QStringLiteral("Language"));

    header->addWidget(logo);
    header->addWidget(brand);
    header->addStretch();
    header->addWidget(languageSelector);
    root->addLayout(header);

    // The secure surface contains status, contacts, encrypted history and message controls.
    auto* surface = new QFrame(&window);
    surface->setObjectName(QStringLiteral("surface"));
    auto* content = new QVBoxLayout(surface);
    content->setContentsMargins(
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg);
    content->setSpacing(enigma::design::kSpacingMd);

    auto* title = new QLabel(l10n(language, "Messagerie sécurisée", "Secure messaging"), surface);
    title->setObjectName(QStringLiteral("headline"));

    auto* status = new QLabel(coreStatus, surface);
    status->setObjectName(QStringLiteral("secure"));
    status->setAccessibleName(coreStatus);

    auto* detail = new QLabel(coreDetail, surface);
    detail->setObjectName(QStringLiteral("body"));
    detail->setWordWrap(true);

    auto* secure = new QLabel(l10n(language, "● Chiffrement de bout en bout", "● End-to-end encrypted"), surface);
    secure->setObjectName(QStringLiteral("secure"));

    auto* pairDevice = new QPushButton(
        coreReady
            ? l10n(language, "Appareil lié", "Device linked")
            : core && core->deviceSessionReady()
                ? l10n(language, "Réessayer la connexion", "Retry connection")
                : l10n(language, "Lier un appareil", "Link a device"),
        surface);
    pairDevice->setAccessibleName(l10n(language, "Lier un appareil Android", "Link an Android device"));
    pairDevice->setEnabled(signalReadyForPairing && !coreReady);
    pairDevice->setToolTip(
        signalReadyForPairing
            ? l10n(language, "Créer un QR d’appairage court-vivant.", "Create a short-lived pairing QR code.")
            : coreDetail);

    auto* openMessages = new QPushButton(l10n(language, "Actualiser", "Refresh"), surface);
    openMessages->setAccessibleName(l10n(language, "Actualiser les messages", "Refresh messages"));
    openMessages->setEnabled(coreReady);
    openMessages->setToolTip(
        coreReady
            ? l10n(language, "Le cœur Rust/libsignal est prêt.", "The Rust/libsignal core is ready.")
            : coreDetail);

    auto* contactSelector = new QComboBox(surface);
    contactSelector->setAccessibleName(l10n(language, "Choisir un contact", "Choose a contact"));
    contactSelector->setEnabled(coreReady);

    auto* messageComposer = new QLineEdit(surface);
    messageComposer->setPlaceholderText(QStringLiteral("Message"));
    messageComposer->setAccessibleName(l10n(language, "Composer un message", "Compose a message"));
    messageComposer->setEnabled(coreReady);

    auto* sendMessage = new QPushButton(l10n(language, "Envoyer", "Send"), surface);
    sendMessage->setAccessibleName(l10n(language, "Envoyer le message", "Send message"));
    sendMessage->setEnabled(coreReady);

    auto* messageList = new QListWidget(surface);
    messageList->setAccessibleName(l10n(language, "Historique des messages chiffrés", "Encrypted message history"));
    messageList->setSelectionMode(QAbstractItemView::NoSelection);
    messageList->setWordWrap(true);
    messageList->setMinimumHeight(220);
    messageList->setSpacing(enigma::design::kSpacingSm);
    messageList->setFrameShape(QFrame::NoFrame);

    // Rebuild the contact model from authenticated core state; malformed JSON is ignored safely.
    const auto refreshContacts = [&core, contactSelector]() {
        contactSelector->clear();
        if (!core || !core->deviceSessionReady()) return;
        const QByteArray contactsJson = QByteArray::fromStdString(core->contactsJson());
        const QJsonDocument contactsDocument = QJsonDocument::fromJson(contactsJson);
        if (!contactsDocument.isArray()) return;
        for (const QJsonValue& value : contactsDocument.array()) {
            const QJsonObject contact = value.toObject();
            const QString userId = contact.value(QStringLiteral("user_id")).toString();
            const QString publicId = contact.value(QStringLiteral("public_id")).toString();
            if (!userId.isEmpty() && !publicId.isEmpty()) {
                contactSelector->addItem(publicId, userId);
            }
        }
    };

    // Render only normalized encrypted-inbox entries that match the selected contact.
    const auto refreshMessages = [&core, contactSelector, messageList, &language, darkTheme]() {
        messageList->clear();
        if (!core || contactSelector->currentIndex() < 0) {
            auto* empty = new QListWidgetItem(
                l10n(language, "Sélectionnez un contact pour afficher la conversation.", "Select a contact to display the conversation."),
                messageList);
            empty->setFlags(Qt::NoItemFlags);
            return;
        }

        const QString selectedContactId = contactSelector->currentData().toString();
        const std::size_t count = core->inboxCount();
        for (std::size_t index = 0; index < count; ++index) {
            const QByteArray encoded =
                QByteArray::fromStdString(core->inboxEntryJson(index));
            const QJsonDocument document = QJsonDocument::fromJson(encoded);
            if (!document.isObject()) continue;
            const QJsonObject entry = document.object();
            if (entry.value(QStringLiteral("contact_user_id")).toString()
                != selectedContactId) {
                continue;
            }

            const QString plaintext =
                entry.value(QStringLiteral("plaintext")).toString();
            const QString payloadPrefix = QStringLiteral("ENIGMA_PAYLOAD_V1:");
            if (!plaintext.startsWith(payloadPrefix)) continue;
            const QByteArray payloadJson = plaintext.mid(payloadPrefix.size()).toUtf8();
            const QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadJson);
            if (!payloadDocument.isObject()) continue;
            const QString body =
                payloadDocument.object().value(QStringLiteral("body")).toString();
            if (body.isEmpty()) continue;

            const bool outbound =
                entry.value(QStringLiteral("direction")).toString() == QStringLiteral("outbound");
            const QString deliveryStatus =
                entry.value(QStringLiteral("delivery_status")).toString();
            QString statusLabel;
            if (outbound) {
                if (deliveryStatus == QStringLiteral("read")) {
                    statusLabel = l10n(language, "Lu", "Read");
                } else if (deliveryStatus == QStringLiteral("delivered")) {
                    statusLabel = l10n(language, "Livré", "Delivered");
                } else if (deliveryStatus == QStringLiteral("sent")) {
                    statusLabel = l10n(language, "Envoyé", "Sent");
                } else if (deliveryStatus == QStringLiteral("queued")) {
                    statusLabel = l10n(language, "En attente", "Queued");
                } else {
                    statusLabel = l10n(language, "Synchronisé", "Synchronized");
                }
            }

            auto* item = new QListWidgetItem(messageList);
            auto* row = new QWidget(messageList);
            auto* rowLayout = new QHBoxLayout(row);
            rowLayout->setContentsMargins(4, 2, 4, 2);
            rowLayout->setSpacing(0);

            auto* bubble = new QFrame(row);
            auto* bubbleLayout = new QVBoxLayout(bubble);
            bubbleLayout->setContentsMargins(14, 10, 14, 9);
            bubbleLayout->setSpacing(3);

            auto* bodyLabel = new QLabel(body, bubble);
            bodyLabel->setWordWrap(true);
            bodyLabel->setMaximumWidth(520);
            bodyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            bubbleLayout->addWidget(bodyLabel);

            if (outbound && !statusLabel.isEmpty()) {
                auto* delivery = new QLabel(statusLabel, bubble);
                delivery->setAlignment(Qt::AlignRight);
                delivery->setStyleSheet(QStringLiteral("font-size: 10px; opacity: 0.78;"));
                bubbleLayout->addWidget(delivery);
            }

            const QString bubbleBackground = outbound
                ? QString::fromUtf8(darkTheme ? enigma::design::kPrimaryDark : enigma::design::kPrimary)
                : QString::fromUtf8(darkTheme ? enigma::design::kSurfaceVariantDark : enigma::design::kSurfaceVariantLight);
            const QString bubbleText = outbound
                ? QString::fromUtf8(darkTheme ? "#101318" : "#FFFFFF")
                : QString::fromUtf8(darkTheme ? "#F7F8FA" : "#171B22");
            bubble->setStyleSheet(
                QStringLiteral(
                    "QFrame { background: %1; border: none; border-radius: 14px; }"
                    "QLabel { color: %2; background: transparent; border: none; }")
                    .arg(bubbleBackground, bubbleText));
            bubble->setMaximumWidth(560);

            if (outbound) {
                rowLayout->addStretch();
                rowLayout->addWidget(bubble, 0, Qt::AlignRight);
            } else {
                rowLayout->addWidget(bubble, 0, Qt::AlignLeft);
                rowLayout->addStretch();
            }

            item->setToolTip(outbound ? statusLabel : l10n(language, "Reçu", "Received"));
            item->setSizeHint(row->sizeHint());
            messageList->setItemWidget(item, row);
        }

        if (messageList->count() == 0) {
            auto* empty = new QListWidgetItem(
                l10n(language, "Aucun message local pour ce contact.", "No local message for this contact."),
                messageList);
            empty->setFlags(Qt::NoItemFlags);
        }
        messageList->scrollToBottom();
    };

    QObject::connect(
        contactSelector,
        &QComboBox::currentIndexChanged,
        [&refreshMessages](int) { refreshMessages(); });
    QFutureWatcher<bool> p2pWatcher(&window);
    QTimer p2pTimer(&window);
    p2pTimer.setInterval(750);
    std::size_t p2pInboxBefore = 0;

    QObject::connect(
        &p2pTimer,
        &QTimer::timeout,
        [&core, &p2pWatcher, &p2pInboxBefore]() {
            if (!core || !core->deviceSessionReady() || p2pWatcher.isRunning()) return;
            p2pInboxBefore = core->inboxCount();
            p2pWatcher.setFuture(QtConcurrent::run([corePointer = core.get()]() {
                return corePointer != nullptr && corePointer->pollP2p();
            }));
        });

    QObject::connect(
        &p2pWatcher,
        &QFutureWatcher<bool>::finished,
        [&core, &p2pWatcher, &p2pInboxBefore, detail, &refreshMessages, &language]() {
            if (!core) return;
            const bool healthy = p2pWatcher.result();
            const std::size_t after = core->inboxCount();
            if (healthy && after != p2pInboxBefore) {
                refreshMessages();
                detail->setText(
                    l10n(
                        language,
                        "P2P E2EE reçu • %1 message(s) local(aux) • fallback relais disponible",
                        "P2P E2EE received • %1 local message(s) • relay fallback available")
                        .arg(static_cast<qulonglong>(after)));
            }
        });

    if (coreReady) {
        p2pTimer.start();
    }

    QObject::connect(
        openMessages,
        &QPushButton::clicked,
        [&core,
         detail,
         contactSelector,
         messageComposer,
         sendMessage,
         openMessages,
         &refreshContacts,
         &refreshMessages,
         messageList,
         &language]() {
            if (!core || !core->deviceSessionReady()) return;

            openMessages->setEnabled(false);
            sendMessage->setEnabled(false);
            contactSelector->setEnabled(false);
            messageComposer->setEnabled(false);

            const bool outboundFlushed = core->retryOutbox();
            const bool synchronized = core->syncPending();
            refreshContacts();
            refreshMessages();

            const std::size_t inboxCount = core->inboxCount();
            const std::size_t outboxCount = core->outboxCount();
            detail->setText(
                synchronized && outboundFlushed
                    ? l10n(language, "Synchronisation à jour • %1 message(s) local(aux)", "Synchronization up to date • %1 local message(s)")
                          .arg(static_cast<qulonglong>(inboxCount))
                    : l10n(language, "Synchronisation partielle • %1 livraison(s) en attente", "Partial synchronization • %1 pending delivery item(s)")
                          .arg(static_cast<qulonglong>(outboxCount)));

            contactSelector->setEnabled(true);
            messageComposer->setEnabled(true);
            sendMessage->setEnabled(true);
            openMessages->setEnabled(true);
            messageList->setFocus();
        });

    if (coreReady) {
        refreshContacts();
        refreshMessages();
    }

    // Queue outbound plaintext through the Rust core; the frontend never implements encryption.
    QObject::connect(
        sendMessage,
        &QPushButton::clicked,
        [&core,
         contactSelector,
         messageComposer,
         detail,
         sendMessage,
         &refreshMessages,
         &language]() {
            if (!core || contactSelector->currentIndex() < 0) return;
            const QString plaintext = messageComposer->text().trimmed();
            if (plaintext.isEmpty()) return;

            const QString userId = contactSelector->currentData().toString();
            sendMessage->setEnabled(false);
            messageComposer->setEnabled(false);
            const bool queued = core->sendTextToContact(
                userId.toStdString(),
                plaintext.toStdString());
            const std::size_t pending = core->outboxCount();

            if (queued) {
                messageComposer->clear();
                refreshMessages();
                detail->setText(
                    pending == 0
                        ? l10n(
                              language,
                              "Message chiffré et remis à tous les appareils disponibles.",
                              "Encrypted message delivered to all available devices.")
                        : l10n(
                              language,
                              "Message chiffré • %1 livraison(s) durablement en attente.",
                              "Encrypted message • %1 durable delivery item(s) pending.")
                              .arg(static_cast<qulonglong>(pending)));
            } else {
                detail->setText(
                    l10n(language, "Échec de la mise en file chiffrée du message.", "Failed to queue the encrypted message."));
            }
            messageComposer->setEnabled(true);
            sendMessage->setEnabled(true);
        });

    // Device linking delegates authorization, libsignal state and replay protection to the core.
    QObject::connect(
        pairDevice,
        &QPushButton::clicked,
        [&window,
         &core,
         status,
         detail,
         contactSelector,
         messageComposer,
         sendMessage,
         openMessages,
         &p2pTimer,
         &refreshContacts,
         &refreshMessages,
         &language,
         pairDevice,
         &coreReady]() {
        if (!core || !core->signalReady()) return;

        if (core->deviceSessionReady()) {
            pairDevice->setEnabled(false);
            detail->setText(l10n(
                language,
                "Réinitialisation de la connexion sécurisée…",
                "Retrying secure connection…"));
            if (!core->initializeDevice()) {
                status->setText(l10n(
                    language,
                    "Session liée • initialisation réseau requise",
                    "Linked session • network initialization required"));
                detail->setText(l10n(
                    language,
                    "Ordinateur autorisé, mais l’initialisation réseau a échoué. Réessayez.",
                    "Computer authorized, but network initialization failed. Retry."));
                pairDevice->setText(l10n(language, "Réessayer la connexion", "Retry connection"));
                pairDevice->setEnabled(true);
                return;
            }

            coreReady = true;
            const bool outboundFlushed = core->retryOutbox();
            const bool synchronized = core->syncPending();
            status->setText(l10n(language, "Cœur sécurisé prêt • appareil lié", "Secure core ready • device linked"));
            detail->setText(
                synchronized && outboundFlushed
                    ? l10n(language, "Rust/libsignal • synchronisation à jour", "Rust/libsignal • synchronization up to date")
                    : l10n(language, "Rust/libsignal • synchronisation à réessayer", "Rust/libsignal • synchronization needs retry"));
            contactSelector->setEnabled(true);
            messageComposer->setEnabled(true);
            sendMessage->setEnabled(true);
            openMessages->setEnabled(true);
            refreshContacts();
            refreshMessages();
            p2pTimer.start();
            pairDevice->setText(l10n(language, "Appareil lié", "Device linked"));
            return;
        }

        if (!core->startPairing()) return;

        const std::string svg = core->pairingSvg();
        const std::string uri = core->pairingUri();
        const std::uint64_t expiresAtUnixMs = core->pairingExpiresAtUnixMs();
        if (svg.empty() || uri.empty() || expiresAtUnixMs == 0) {
            core->cancelPairing();
            return;
        }

        QDialog dialog(&window);
        dialog.setWindowTitle(l10n(language, "Lier cet ordinateur", "Link this computer"));
        dialog.setModal(true);
        auto* layout = new QVBoxLayout(&dialog);
        layout->setContentsMargins(20, 20, 20, 20);
        layout->setSpacing(12);

        auto* instructions = new QLabel(
            l10n(language, "Scannez ce code depuis ENIGMA sur votre appareil Android autorisé.", "Scan this code from ENIGMA on your authorized Android device."),
            &dialog);
        instructions->setWordWrap(true);

        auto* qr = new QSvgWidget(&dialog);
        qr->load(QByteArray::fromStdString(svg));
        qr->setFixedSize(320, 320);

        const auto expiresAt = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(expiresAtUnixMs));
        auto* expiry = new QLabel(
            l10n(language, "Expire à %1", "Expires at %1").arg(expiresAt.toLocalTime().toString(QStringLiteral("HH:mm:ss"))),
            &dialog);

        auto* uriField = new QLineEdit(QString::fromStdString(uri), &dialog);
        uriField->setReadOnly(true);
        uriField->setAccessibleName(l10n(language, "URI d’appairage", "Pairing URI"));

        auto* pairingStatus = new QLabel(
            l10n(language, "En attente de l’autorisation Android…", "Waiting for Android authorization…"),
            &dialog);
        pairingStatus->setWordWrap(true);

        auto* finalize = new QPushButton(l10n(language, "Finaliser la liaison", "Finish linking"), &dialog);
        QObject::connect(
            finalize,
            &QPushButton::clicked,
            [&dialog,
             &core,
             pairingStatus,
             finalize,
             status,
             detail,
             contactSelector,
             messageComposer,
             sendMessage,
             openMessages,
             &p2pTimer,
             &refreshContacts,
             &refreshMessages,
             &language,
             pairDevice,
             &coreReady]() {
            if (!core) return;
            finalize->setEnabled(false);
            const std::uint32_t claimState = core->deviceSessionReady()
                ? ENIGMA_PAIRING_CLAIMED
                : core->claimPairing();
            const auto finalizeClaimedPairing = [&]() {
                pairingStatus->setText(
                    l10n(language, "Session autorisée. Publication des clés libsignal…", "Session authorized. Publishing libsignal keys…"));
                if (core->initializeDevice()) {
                    const bool outboundFlushed = core->retryOutbox();
                    const bool synchronized = core->syncPending();
                    pairingStatus->setText(
                        synchronized && outboundFlushed
                            ? l10n(language, "Ordinateur lié et synchronisé avec succès.", "Computer linked and synchronized successfully.")
                            : l10n(
                                  language,
                                  "Ordinateur lié. La synchronisation sera réessayée.",
                                  "Computer linked. Synchronization will be retried."));
                    coreReady = true;
                    status->setText(l10n(language, "Cœur sécurisé prêt • appareil lié", "Secure core ready • device linked"));
                    pairDevice->setText(l10n(language, "Appareil lié", "Device linked"));
                    pairDevice->setEnabled(false);
                    contactSelector->setEnabled(true);
                    messageComposer->setEnabled(true);
                    sendMessage->setEnabled(true);
                    openMessages->setEnabled(true);
                    refreshContacts();
                    refreshMessages();
                    p2pTimer.start();
                    detail->setText(
                        synchronized && outboundFlushed
                            ? l10n(language, "Rust/libsignal • synchronisation à jour", "Rust/libsignal • synchronization up to date")
                            : l10n(language, "Rust/libsignal • synchronisation à réessayer", "Rust/libsignal • synchronization needs retry"));
                    dialog.accept();
                    return;
                }

                pairingStatus->setText(l10n(
                    language,
                    "Ordinateur autorisé, mais l’initialisation réseau a échoué. Réessayez sans rescanner le QR.",
                    "Computer authorized, but network initialization failed. Retry without scanning the QR again."));
                finalize->setText(l10n(language, "Réessayer l’initialisation", "Retry initialization"));
                finalize->setEnabled(true);
            };

            switch (claimState) {
                case ENIGMA_PAIRING_CLAIMED:
                    finalizeClaimedPairing();
                    break;
                case ENIGMA_PAIRING_CLAIM_PENDING:
                    pairingStatus->setText(
                        l10n(language, "Autorisez d’abord cet ordinateur depuis Android.", "Authorize this computer from Android first."));
                    finalize->setEnabled(true);
                    break;
                case ENIGMA_PAIRING_CLAIM_EXPIRED:
                    pairingStatus->setText(l10n(language, "La session d’appairage a expiré.", "The pairing session expired."));
                    break;
                case ENIGMA_PAIRING_CLAIM_ALREADY_USED:
                    pairingStatus->setText(
                        l10n(language, "Cette session d’appairage a déjà été utilisée.", "This pairing session has already been used."));
                    break;
                case ENIGMA_PAIRING_CLAIM_MISSING:
                    pairingStatus->setText(l10n(language, "Session d’appairage introuvable.", "Pairing session not found."));
                    break;
                default:
                    pairingStatus->setText(
                        l10n(language, "Le serveur d’appairage est momentanément indisponible.", "The pairing server is temporarily unavailable."));
                    finalize->setEnabled(true);
                    break;
            }
        });

        auto* close = new QPushButton(l10n(language, "Fermer", "Close"), &dialog);
        QObject::connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);

        layout->addWidget(instructions);
        layout->addWidget(qr, 0, Qt::AlignHCenter);
        layout->addWidget(expiry);
        layout->addWidget(uriField);
        layout->addWidget(pairingStatus);
        layout->addWidget(finalize, 0, Qt::AlignLeft);
        layout->addWidget(close, 0, Qt::AlignRight);

        dialog.exec();
        core->cancelPairing();
    });

    QObject::connect(
        languageSelector,
        &QComboBox::currentIndexChanged,
        [&language,
         languageSelector,
         title,
         secure,
         pairDevice,
         openMessages,
         contactSelector,
         messageComposer,
         sendMessage,
         status,
         detail,
         &core,
         &coreReady,
         signalReadyForPairing,
         &refreshMessages,
         &settings](int index) {
            const auto selected = static_cast<UiLanguage>(languageSelector->itemData(index).toInt());
            if (selected == language) return;
            language = selected;
            settings.setValue(
                QStringLiteral("ui/language"),
                language == UiLanguage::French ? QStringLiteral("fr") : QStringLiteral("en"));
            title->setText(l10n(language, "Messagerie sécurisée", "Secure messaging"));
            secure->setText(l10n(language, "● Chiffrement de bout en bout", "● End-to-end encrypted"));
            pairDevice->setText(
                coreReady
                    ? l10n(language, "Appareil lié", "Device linked")
                    : core && core->deviceSessionReady()
                        ? l10n(language, "Réessayer la connexion", "Retry connection")
                        : l10n(language, "Lier un appareil", "Link a device"));
            pairDevice->setEnabled(signalReadyForPairing && !coreReady);
            pairDevice->setAccessibleName(l10n(language, "Lier un appareil Android", "Link an Android device"));
            openMessages->setText(l10n(language, "Actualiser", "Refresh"));
            openMessages->setAccessibleName(l10n(language, "Actualiser les messages", "Refresh messages"));
            contactSelector->setAccessibleName(l10n(language, "Choisir un contact", "Choose a contact"));
            messageComposer->setAccessibleName(l10n(language, "Composer un message", "Compose a message"));
            sendMessage->setText(l10n(language, "Envoyer", "Send"));
            sendMessage->setAccessibleName(l10n(language, "Envoyer le message", "Send message"));
            if (coreReady) {
                status->setText(l10n(language, "Cœur sécurisé prêt • appareil lié", "Secure core ready • device linked"));
                detail->setText(
                    l10n(language, "Rust/libsignal • ABI %1 • %2 message(s) local(aux)", "Rust/libsignal • ABI %1 • %2 local message(s)")
                        .arg(enigma::linked_core_abi_version())
                        .arg(static_cast<qulonglong>(core ? core->inboxCount() : 0)));
            } else if (signalReadyForPairing && core && core->deviceSessionReady()) {
                status->setText(l10n(
                    language,
                    "Session liée • initialisation réseau requise",
                    "Linked session • network initialization required"));
                detail->setText(l10n(
                    language,
                    "Session restaurée • utilisez Réessayer la connexion",
                    "Session restored • use Retry connection"));
            } else if (signalReadyForPairing) {
                status->setText(l10n(language, "Appairage Android requis", "Android pairing required"));
                detail->setText(l10n(language, "Identité libsignal prête • liez cet ordinateur depuis Android", "Libsignal identity ready • link this computer from Android"));
            }
            refreshMessages();
        });

    // Finalize the stable widget hierarchy after all callbacks have captured their dependencies.
    content->addWidget(title);
    content->addWidget(status);
    content->addWidget(detail);
    content->addWidget(secure);
    content->addSpacing(enigma::design::kSpacingSm);
    content->addWidget(pairDevice, 0, Qt::AlignLeft);
    content->addWidget(openMessages, 0, Qt::AlignLeft);
    content->addWidget(messageList, 1);

    auto* composerRow = new QHBoxLayout();
    composerRow->setSpacing(enigma::design::kSpacingSm);
    composerRow->addWidget(contactSelector, 1);
    composerRow->addWidget(messageComposer, 3);
    composerRow->addWidget(sendMessage, 0);
    content->addLayout(composerRow);
    content->addStretch();

    root->addWidget(surface, 1);

    // Enter Qt's event loop only after the initial secure state and UI affordances are consistent.
    window.show();
    const int exitCode = app.exec();
    p2pTimer.stop();
    if (p2pWatcher.isRunning()) {
        p2pWatcher.waitForFinished();
    }
    return exitCode;
}
