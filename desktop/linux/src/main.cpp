#include <QApplication>
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle(QStringLiteral("ENIGMA"));
    window.resize(720, 480);

    auto* layout = new QVBoxLayout(&window);
    auto* title = new QLabel(QStringLiteral("ENIGMA Desktop"), &window);
    auto* status = new QLabel(
        QStringLiteral("Qt 6 shell — cryptographic operations remain confined to the Rust/libsignal core."),
        &window);
    status->setWordWrap(true);

    layout->addWidget(title);
    layout->addWidget(status);
    layout->addStretch();

    window.show();
    return app.exec();
}
