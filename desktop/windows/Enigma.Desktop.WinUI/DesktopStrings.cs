using System;
using System.Globalization;
using System.IO;

namespace Enigma.Desktop.WinUI;

internal enum DesktopLanguage
{
    French,
    English,
}

internal static class DesktopStrings
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ENIGMA",
        "ui-language.txt");

    internal static DesktopLanguage SystemLanguage() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("fr", StringComparison.OrdinalIgnoreCase)
            ? DesktopLanguage.French
            : DesktopLanguage.English;

    internal static DesktopLanguage LoadLanguage()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                return FromCode(File.ReadAllText(SettingsPath).Trim());
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        return SystemLanguage();
    }

    internal static void SaveLanguage(DesktopLanguage language)
    {
        try
        {
            string? directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
            File.WriteAllText(SettingsPath, Code(language));
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    internal static DesktopLanguage FromCode(string code) =>
        code.Equals("fr", StringComparison.OrdinalIgnoreCase)
            ? DesktopLanguage.French
            : DesktopLanguage.English;

    internal static string Code(DesktopLanguage language) =>
        language == DesktopLanguage.French ? "fr" : "en";

    internal static string Get(string key, DesktopLanguage language)
    {
        bool fr = language == DesktopLanguage.French;
        return key switch
        {
            "brand.subtitle" => fr ? "Messagerie chiffrée" : "Encrypted messaging",
            "device.section" => fr ? "Cet appareil" : "This device",
            "device.session" => fr ? "Session desktop" : "Desktop session",
            "header.title" => "ENIGMA Desktop",
            "header.subtitle" => fr
                ? "P2P prioritaire • relais temporaire si nécessaire"
                : "P2P first • temporary relay only when needed",
            "refresh" => fr ? "Actualiser" : "Refresh",
            "devices.pair" => fr ? "Lier cet ordinateur" : "Link this computer",
            "devices.manage" => fr ? "Appareils" : "Devices",
            "crypto.notice" => fr
                ? "Les opérations cryptographiques restent confinées au cœur Rust/libsignal partagé."
                : "Cryptographic operations stay confined to the shared Rust/libsignal core.",
            "contact.choose" => fr ? "Choisir un contact" : "Choose a contact",
            "message.placeholder" => fr ? "Message" : "Message",
            "send" => fr ? "Envoyer" : "Send",
            "status.initializing" => fr ? "Initialisation du cœur sécurisé…" : "Initializing secure core…",
            "status.ready" => fr ? "Cœur sécurisé prêt • appareil lié" : "Secure core ready • device linked",
            "status.session_network" => fr
                ? "Session liée • initialisation réseau requise"
                : "Linked session • network initialization required",
            "status.pair_required" => fr ? "Appairage Android requis" : "Android pairing required",
            "status.identity_required" => fr ? "Identité E2EE protégée requise" : "Protected E2EE identity required",
            "status.unavailable" => fr ? "Cœur sécurisé indisponible" : "Secure core unavailable",
            "detail.ready" => fr
                ? "Rust/libsignal • ABI {0} • {1} message(s) local(aux)"
                : "Rust/libsignal • ABI {0} • {1} local message(s)",
            "detail.pending" => fr
                ? "Rust/libsignal • ABI {0} • {1} livraison(s) en attente"
                : "Rust/libsignal • ABI {0} • {1} pending delivery item(s)",
            "detail.session_retry" => fr
                ? "Session device restaurée, mais la publication des prekeys doit être réessayée"
                : "Device session restored, but pre-key publication must be retried",
            "detail.pair_hint" => fr
                ? "Identité libsignal prête • liez cet ordinateur depuis Android"
                : "Libsignal identity ready • link this computer from Android",
            "detail.identity_missing" => fr
                ? "Rust chargé • ABI {0} • identité libsignal non restaurée"
                : "Rust loaded • ABI {0} • libsignal identity not restored",
            "detail.core_not_ready" => fr ? "Le cœur Rust n’est pas prêt" : "The Rust core is not ready",
            "core.native_missing" => fr ? "Bibliothèque native ENIGMA introuvable" : "ENIGMA native library not found",
            "core.native_incompatible" => fr ? "Bibliothèque native ENIGMA incompatible" : "ENIGMA native library is incompatible",
            "core.abi_incompatible" => fr ? "Version ABI ENIGMA incompatible" : "ENIGMA ABI version is incompatible",
            "core.init_failed" => fr ? "Initialisation du cœur ENIGMA impossible" : "Unable to initialize the ENIGMA core",
            "p2p.received" => fr
                ? "P2P E2EE reçu • {0} message(s) local(aux) • fallback relais disponible"
                : "P2P E2EE received • {0} local message(s) • relay fallback available",
            "pair.create_failed" => fr ? "Création de la session d’appairage impossible" : "Unable to create pairing session",
            "pair.title" => fr ? "Lier cet ordinateur" : "Link this computer",
            "pair.scan" => fr
                ? "Scannez ce code depuis ENIGMA sur votre appareil Android autorisé."
                : "Scan this code from ENIGMA on your authorized Android device.",
            "pair.expires" => fr ? "Expire à {0}" : "Expires at {0}",
            "pair.uri" => fr ? "URI d’appairage" : "Pairing URI",
            "pair.wait" => fr ? "En attente de l’autorisation Android…" : "Waiting for Android authorization…",
            "pair.finalize" => fr ? "Finaliser la liaison" : "Finish linking",
            "pair.close" => fr ? "Fermer" : "Close",
            "pair.authorized_keys" => fr
                ? "Session autorisée. Publication des clés libsignal…"
                : "Session authorized. Publishing libsignal keys…",
            "pair.success" => fr ? "Ordinateur lié et synchronisé avec succès." : "Computer linked and synchronized successfully.",
            "pair.linked" => fr ? "Ordinateur lié avec succès." : "Computer linked successfully.",
            "pair.sync_retry" => fr ? "Ordinateur lié. La synchronisation sera réessayée." : "Computer linked. Synchronization will be retried.",
            "pair.sync_ok_detail" => fr ? "Rust/libsignal • synchronisation à jour" : "Rust/libsignal • synchronization up to date",
            "pair.sync_retry_detail" => fr ? "Rust/libsignal • synchronisation à réessayer" : "Rust/libsignal • synchronization needs retry",
            "pair.init_failed" => fr
                ? "Ordinateur autorisé, mais l’initialisation réseau a échoué. Réessayez sans rescanner le QR."
                : "Computer authorized, but network initialization failed. Retry without scanning the QR again.",
            "pair.retry_init" => fr ? "Réessayer l’initialisation" : "Retry initialization",
            "pair.authorize_first" => fr ? "Autorisez d’abord cet ordinateur depuis Android." : "Authorize this computer from Android first.",
            "pair.expired" => fr ? "La session d’appairage a expiré." : "The pairing session expired.",
            "pair.used" => fr ? "Cette session d’appairage a déjà été utilisée." : "This pairing session has already been used.",
            "pair.missing" => fr ? "Session d’appairage introuvable." : "Pairing session not found.",
            "pair.server_unavailable" => fr
                ? "Le serveur d’appairage est momentanément indisponible."
                : "The pairing server is temporarily unavailable.",
            "pair.fallback_title" => fr ? "Appairage ENIGMA" : "ENIGMA pairing",
            "contacts.invalid" => fr ? "La liste de contacts reçue est invalide." : "The received contact list is invalid.",
            "message.read" => fr ? "Lu" : "Read",
            "message.delivered" => fr ? "Livré" : "Delivered",
            "message.sent" => fr ? "Envoyé" : "Sent",
            "message.queued" => fr ? "En attente" : "Queued",
            "message.synced" => fr ? "Synchronisé" : "Synchronized",
            "message.select_contact" => fr
                ? "Sélectionnez un contact pour afficher la conversation."
                : "Select a contact to display the conversation.",
            "message.none" => fr ? "Aucun message local pour ce contact." : "No local message for this contact.",
            "sync.ready" => fr
                ? "Synchronisation à jour • {0} message(s) local(aux)"
                : "Synchronization up to date • {0} local message(s)",
            "sync.partial" => fr
                ? "Synchronisation partielle • {0} livraison(s) en attente"
                : "Partial synchronization • {0} pending delivery item(s)",
            "send.choose_contact" => fr ? "Choisissez un contact avant d’envoyer." : "Choose a contact before sending.",
            "send.delivered" => fr
                ? "Message chiffré et remis à tous les appareils disponibles."
                : "Encrypted message delivered to all available devices.",
            "send.pending" => fr
                ? "Message chiffré • {0} livraison(s) durablement en attente."
                : "Encrypted message • {0} durable delivery item(s) pending.",
            "send.failed" => fr ? "Échec de la mise en file chiffrée du message." : "Failed to queue the encrypted message.",
            _ => key,
        };
    }
}
