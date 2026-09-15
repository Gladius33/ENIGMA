#include <QApplication>
#include <QDateTime>
#include <QDialog>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPixmap>
#include <QPushButton>
#include <QSvgWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <exception>
#include <memory>

#include "../../design/enigma_tokens.hpp"
#include "enigma_core.hpp"

namespace {

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
               "QPushButton:disabled { background: %4; color: %6; }")
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
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("ENIGMA"));
    app.setOrganizationName(QStringLiteral("ENIGMA"));

    std::unique_ptr<enigma::Core> core;
    bool coreReady = false;
    QString coreStatus = QStringLiteral("Cœur sécurisé indisponible");
    QString coreDetail = QStringLiteral("Le cœur Rust/libsignal n’est pas prêt");

    try {
        core = std::make_unique<enigma::Core>();
        const bool runtimeReady = core->ready();
        const bool signalReady = runtimeReady
            && (core->signalReady() || core->ensureDefaultSignalIdentity());
        coreReady = signalReady;
        if (signalReady) {
            coreStatus = QStringLiteral("Cœur sécurisé prêt");
            coreDetail = QStringLiteral("Rust/libsignal • ABI %1").arg(enigma::linked_core_abi_version());
        } else if (runtimeReady) {
            coreStatus = QStringLiteral("Identité E2EE protégée requise");
            coreDetail = QStringLiteral("Rust chargé • ABI %1 • identité libsignal non restaurée")
                             .arg(enigma::linked_core_abi_version());
        }
    } catch (const std::exception& error) {
        coreDetail = QStringLiteral("Initialisation du cœur ENIGMA impossible : %1")
                         .arg(QString::fromUtf8(error.what()));
    }

    QWidget window;
    window.setObjectName(QStringLiteral("root"));
    window.setWindowTitle(QStringLiteral("ENIGMA"));
    window.resize(860, 560);
    window.setMinimumSize(640, 420);
    window.setStyleSheet(buildStyleSheet(isDarkPalette(app.palette())));

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

    header->addWidget(logo);
    header->addWidget(brand);
    header->addStretch();
    root->addLayout(header);

    auto* surface = new QFrame(&window);
    surface->setObjectName(QStringLiteral("surface"));
    auto* content = new QVBoxLayout(surface);
    content->setContentsMargins(
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg,
        enigma::design::kSpacingLg);
    content->setSpacing(enigma::design::kSpacingMd);

    auto* title = new QLabel(QStringLiteral("Messagerie sécurisée"), surface);
    title->setObjectName(QStringLiteral("headline"));

    auto* status = new QLabel(coreStatus, surface);
    status->setObjectName(QStringLiteral("secure"));
    status->setAccessibleName(coreStatus);

    auto* detail = new QLabel(coreDetail, surface);
    detail->setObjectName(QStringLiteral("body"));
    detail->setWordWrap(true);

    auto* secure = new QLabel(QStringLiteral("● Chiffrement de bout en bout"), surface);
    secure->setObjectName(QStringLiteral("secure"));

    auto* pairDevice = new QPushButton(QStringLiteral("Lier un appareil"), surface);
    pairDevice->setAccessibleName(QStringLiteral("Lier un appareil Android"));
    pairDevice->setEnabled(coreReady);
    pairDevice->setToolTip(
        coreReady
            ? QStringLiteral("Créer un QR d’appairage court-vivant.")
            : coreDetail);

    auto* openMessages = new QPushButton(QStringLiteral("Ouvrir les messages"), surface);
    openMessages->setAccessibleName(QStringLiteral("Ouvrir les messages"));
    openMessages->setEnabled(coreReady);
    openMessages->setToolTip(
        coreReady
            ? QStringLiteral("Le cœur Rust/libsignal est prêt.")
            : coreDetail);

    QObject::connect(pairDevice, &QPushButton::clicked, [&window, &core]() {
        if (!core || !core->signalReady() || !core->startPairing()) return;

        const std::string svg = core->pairingSvg();
        const std::string uri = core->pairingUri();
        const std::uint64_t expiresAtUnixMs = core->pairingExpiresAtUnixMs();
        if (svg.empty() || uri.empty() || expiresAtUnixMs == 0) {
            core->cancelPairing();
            return;
        }

        QDialog dialog(&window);
        dialog.setWindowTitle(QStringLiteral("Lier cet ordinateur"));
        dialog.setModal(true);
        auto* layout = new QVBoxLayout(&dialog);
        layout->setContentsMargins(20, 20, 20, 20);
        layout->setSpacing(12);

        auto* instructions = new QLabel(
            QStringLiteral("Scannez ce code depuis ENIGMA sur votre appareil Android autorisé."),
            &dialog);
        instructions->setWordWrap(true);

        auto* qr = new QSvgWidget(&dialog);
        qr->load(QByteArray::fromStdString(svg));
        qr->setFixedSize(320, 320);

        const auto expiresAt = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(expiresAtUnixMs));
        auto* expiry = new QLabel(
            QStringLiteral("Expire à %1").arg(expiresAt.toLocalTime().toString(QStringLiteral("HH:mm:ss"))),
            &dialog);

        auto* uriField = new QLineEdit(QString::fromStdString(uri), &dialog);
        uriField->setReadOnly(true);
        uriField->setAccessibleName(QStringLiteral("URI d’appairage"));

        auto* close = new QPushButton(QStringLiteral("Fermer"), &dialog);
        QObject::connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);

        layout->addWidget(instructions);
        layout->addWidget(qr, 0, Qt::AlignHCenter);
        layout->addWidget(expiry);
        layout->addWidget(uriField);
        layout->addWidget(close, 0, Qt::AlignRight);

        dialog.exec();
        core->cancelPairing();
    });

    content->addWidget(title);
    content->addWidget(status);
    content->addWidget(detail);
    content->addWidget(secure);
    content->addSpacing(enigma::design::kSpacingSm);
    content->addWidget(pairDevice, 0, Qt::AlignLeft);
    content->addWidget(openMessages, 0, Qt::AlignLeft);
    content->addStretch();

    root->addWidget(surface, 1);

    window.show();
    return app.exec();
}
