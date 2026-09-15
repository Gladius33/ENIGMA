using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Enigma.Desktop.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;

namespace Enigma.Desktop.WinUI;

public sealed partial class MainWindow : Window
{
    private readonly DispatcherTimer _p2pPollTimer = new();
    private EnigmaCoreClient? _core;
    private bool _p2pPollInFlight;

    public MainWindow()
    {
        InitializeComponent();
        Closed += OnClosed;
        ContactSelector.SelectionChanged += OnContactSelectionChanged;
        _p2pPollTimer.Interval = TimeSpan.FromMilliseconds(750);
        _p2pPollTimer.Tick += OnP2pPollTick;
        InitializeSecureCore();
    }

    private async void InitializeSecureCore()
    {
        try
        {
            _core = new EnigmaCoreClient();
            bool runtimeReady = _core.IsReady;
            bool signalReady = runtimeReady &&
                (_core.SignalReady || _core.EnsureDefaultSignalIdentity());
            bool sessionReady = signalReady && _core.DeviceSessionReady;
            bool deviceReady = sessionReady && await Task.Run(() => _core.InitializeDevice());
            bool operationalReady = signalReady && sessionReady && deviceReady;
            bool outboxFlushed = operationalReady && await Task.Run(() => _core.RetryOutbox());
            bool inboxSynced = operationalReady && await Task.Run(() => _core.SyncPending());
            nuint inboxCount = operationalReady ? _core.InboxCount : 0;
            nuint outboxCount = operationalReady ? _core.OutboxCount : 0;

            CoreStatusText.Text = operationalReady
                ? "Cœur sécurisé prêt • appareil lié"
                : signalReady
                    ? sessionReady
                        ? "Session liée • initialisation réseau requise"
                        : "Appairage Android requis"
                    : runtimeReady
                        ? "Identité E2EE protégée requise"
                        : "Cœur sécurisé indisponible";
            CoreDetailText.Text = operationalReady
                ? inboxSynced && outboxFlushed
                    ? $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion} • {inboxCount} message(s) local(aux)"
                    : $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion} • {outboxCount} livraison(s) en attente"
                : signalReady
                    ? sessionReady
                        ? "Session device restaurée, mais la publication des prekeys doit être réessayée"
                        : "Identité libsignal prête • liez cet ordinateur depuis Android"
                    : runtimeReady
                        ? $"Rust chargé • ABI {EnigmaCoreClient.AbiVersion} • identité libsignal non restaurée"
                        : "Le cœur Rust n’est pas prêt";

            MessageComposer.IsEnabled = operationalReady;
            ContactSelector.IsEnabled = operationalReady;
            SendButton.IsEnabled = operationalReady;
            RefreshButton.IsEnabled = operationalReady;
            DevicesButton.IsEnabled = signalReady;
            if (operationalReady)
            {
                RefreshContacts();
                RefreshMessages();
                _p2pPollTimer.Start();
            }
        }
        catch (DllNotFoundException)
        {
            SetCoreUnavailable("Bibliothèque native ENIGMA introuvable");
        }
        catch (BadImageFormatException)
        {
            SetCoreUnavailable("Bibliothèque native ENIGMA incompatible");
        }
        catch (NotSupportedException)
        {
            SetCoreUnavailable("Version ABI ENIGMA incompatible");
        }
        catch (InvalidOperationException)
        {
            SetCoreUnavailable("Initialisation du cœur ENIGMA impossible");
        }
    }

    private void SetCoreUnavailable(string detail)
    {
        CoreStatusText.Text = "Cœur sécurisé indisponible";
        CoreDetailText.Text = detail;
        MessageComposer.IsEnabled = false;
        ContactSelector.IsEnabled = false;
        SendButton.IsEnabled = false;
        RefreshButton.IsEnabled = false;
        _p2pPollTimer.Stop();
    }

    private async void OnP2pPollTick(object? sender, object args)
    {
        if (_p2pPollInFlight || _core is null || !_core.DeviceSessionReady)
        {
            return;
        }

        _p2pPollInFlight = true;
        try
        {
            nuint before = _core.InboxCount;
            bool healthy = await Task.Run(() => _core.PollP2p());
            nuint after = _core.InboxCount;
            if (healthy && after != before)
            {
                RefreshMessages();
                CoreDetailText.Text =
                    $"P2P E2EE reçu • {after} message(s) local(aux) • relay fallback disponible";
            }
        }
        catch (ObjectDisposedException)
        {
            _p2pPollTimer.Stop();
        }
        finally
        {
            _p2pPollInFlight = false;
        }
    }

    private async void OnManageDevicesClick(object sender, RoutedEventArgs args)
    {
        if (_core is null || !_core.SignalReady)
        {
            return;
        }

        EnigmaPairingBootstrap? pairing = _core.StartPairing();
        if (pairing is null)
        {
            SetCoreUnavailable("Création de la session d’appairage impossible");
            return;
        }

        try
        {
            byte[] svgBytes = Encoding.UTF8.GetBytes(pairing.Svg);
            using var stream = new InMemoryRandomAccessStream();
            using (var writer = new DataWriter(stream))
            {
                writer.WriteBytes(svgBytes);
                await writer.StoreAsync();
                writer.DetachStream();
            }
            stream.Seek(0);

            var svgSource = new SvgImageSource();
            SvgImageSourceLoadStatus loadStatus = await svgSource.SetSourceAsync(stream);
            if (loadStatus != SvgImageSourceLoadStatus.Success)
            {
                throw new InvalidOperationException("Le QR d’appairage n’a pas pu être rendu");
            }

            DateTimeOffset expiresAt = DateTimeOffset
                .FromUnixTimeMilliseconds(checked((long)pairing.ExpiresAtUnixMs))
                .ToLocalTime();

            var panel = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 420,
            };
            panel.Children.Add(new TextBlock
            {
                Text = "Scannez ce code depuis ENIGMA sur votre appareil Android autorisé.",
                TextWrapping = TextWrapping.Wrap,
            });
            panel.Children.Add(new Image
            {
                Width = 320,
                Height = 320,
                Source = svgSource,
            });
            panel.Children.Add(new TextBlock
            {
                Text = $"Expire à {expiresAt:HH:mm:ss}",
                Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["EnigmaMutedTextBrush"],
            });
            panel.Children.Add(new TextBox
            {
                Header = "URI d’appairage",
                Text = pairing.Uri,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
            });

            var pairingStatus = new TextBlock
            {
                Text = "En attente de l’autorisation Android…",
                TextWrapping = TextWrapping.Wrap,
            };
            var finalizeButton = new Button
            {
                Content = "Finaliser la liaison",
                HorizontalAlignment = HorizontalAlignment.Left,
            };
            panel.Children.Add(pairingStatus);
            panel.Children.Add(finalizeButton);

            var dialog = new ContentDialog
            {
                XamlRoot = DevicesButton.XamlRoot,
                Title = "Lier cet ordinateur",
                Content = panel,
                CloseButtonText = "Fermer",
                DefaultButton = ContentDialogButton.Close,
            };

            finalizeButton.Click += async (_, _) =>
            {
                if (_core is null)
                {
                    return;
                }
                finalizeButton.IsEnabled = false;
                EnigmaPairingClaimState state = _core.DeviceSessionReady
                    ? EnigmaPairingClaimState.Claimed
                    : await Task.Run(() => _core.TryClaimPairing());
                switch (state)
                {
                    case EnigmaPairingClaimState.Claimed:
                        pairingStatus.Text = "Session autorisée. Publication des clés libsignal…";
                        bool initialized = await Task.Run(() => _core.InitializeDevice());
                        if (initialized)
                        {
                            pairingStatus.Text = "Ordinateur lié avec succès.";
                            CoreStatusText.Text = "Cœur sécurisé prêt • appareil lié";
                            bool outboxFlushed = await Task.Run(() => _core.RetryOutbox());
                            bool synchronized = await Task.Run(() => _core.SyncPending());
                            nuint inboxCount = _core.InboxCount;
                            nuint outboxCount = _core.OutboxCount;
                            CoreDetailText.Text = synchronized && outboxFlushed
                                ? $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion} • {inboxCount} message(s) local(aux)"
                                : $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion} • {outboxCount} livraison(s) en attente";
                            MessageComposer.IsEnabled = true;
                            ContactSelector.IsEnabled = true;
                            SendButton.IsEnabled = true;
                            RefreshButton.IsEnabled = true;
                            RefreshContacts();
                            RefreshMessages();
                            _p2pPollTimer.Start();
                            dialog.Hide();
                        }
                        else
                        {
                            pairingStatus.Text =
                                "Ordinateur autorisé, mais l’initialisation réseau a échoué. Réessayez sans rescanner le QR.";
                            finalizeButton.Content = "Réessayer l’initialisation";
                            finalizeButton.IsEnabled = true;
                        }
                        break;
                    case EnigmaPairingClaimState.PendingAuthorization:
                        pairingStatus.Text = "Autorisez d’abord cet ordinateur depuis Android.";
                        finalizeButton.IsEnabled = true;
                        break;
                    case EnigmaPairingClaimState.Expired:
                        pairingStatus.Text = "La session d’appairage a expiré.";
                        break;
                    case EnigmaPairingClaimState.AlreadyClaimed:
                        pairingStatus.Text = "Cette session d’appairage a déjà été utilisée.";
                        break;
                    case EnigmaPairingClaimState.Missing:
                        pairingStatus.Text = "Session d’appairage introuvable.";
                        break;
                    default:
                        pairingStatus.Text = "Le serveur d’appairage est momentanément indisponible.";
                        finalizeButton.IsEnabled = true;
                        break;
                }
            };

            await dialog.ShowAsync();
        }
        catch (InvalidOperationException)
        {
            var fallback = new ContentDialog
            {
                XamlRoot = DevicesButton.XamlRoot,
                Title = "Appairage ENIGMA",
                Content = pairing.Uri,
                CloseButtonText = "Fermer",
            };
            await fallback.ShowAsync();
        }
        finally
        {
            _core.CancelPairing();
        }
    }

    private void RefreshContacts()
    {
        if (_core is null || !_core.DeviceSessionReady)
        {
            return;
        }

        ContactSelector.Items.Clear();
        try
        {
            using JsonDocument document = JsonDocument.Parse(_core.ReadContactsJson());
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (JsonElement contact in document.RootElement.EnumerateArray())
            {
                if (!contact.TryGetProperty("user_id", out JsonElement userIdElement) ||
                    !contact.TryGetProperty("public_id", out JsonElement publicIdElement))
                {
                    continue;
                }
                string? userId = userIdElement.GetString();
                string? publicId = publicIdElement.GetString();
                if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(publicId))
                {
                    continue;
                }
                ContactSelector.Items.Add(new ComboBoxItem
                {
                    Content = publicId,
                    Tag = userId,
                });
            }

            if (ContactSelector.Items.Count > 0)
            {
                ContactSelector.SelectedIndex = 0;
            }
        }
        catch (JsonException)
        {
            CoreDetailText.Text = "La liste de contacts reçue est invalide.";
        }
    }

    private void OnContactSelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        RefreshMessages();
    }

    private static string DecodeMessageBody(string encodedPayload)
    {
        const string prefix = "ENIGMA_PAYLOAD_V1:";
        if (!encodedPayload.StartsWith(prefix, StringComparison.Ordinal))
        {
            return string.Empty;
        }

        try
        {
            using JsonDocument payload = JsonDocument.Parse(encodedPayload[prefix.Length..]);
            return payload.RootElement.TryGetProperty("body", out JsonElement body)
                ? body.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    private void RefreshMessages()
    {
        if (_core is null)
        {
            return;
        }

        string? selectedContactId = (ContactSelector.SelectedItem as ComboBoxItem)?.Tag as string;
        MessagesPanel.Children.Clear();

        nuint count = _core.InboxCount;
        for (nuint index = 0; index < count; index++)
        {
            string encoded = _core.ReadInboxEntryJson(index);
            if (string.IsNullOrWhiteSpace(encoded))
            {
                continue;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(encoded);
                JsonElement root = document.RootElement;
                string? contactUserId =
                    root.TryGetProperty("contact_user_id", out JsonElement contact)
                        ? contact.GetString()
                        : null;
                if (!string.IsNullOrWhiteSpace(selectedContactId) &&
                    contactUserId != selectedContactId)
                {
                    continue;
                }

                string direction =
                    root.TryGetProperty("direction", out JsonElement directionElement)
                        ? directionElement.GetString() ?? "inbound"
                        : "inbound";
                string plaintext =
                    root.TryGetProperty("plaintext", out JsonElement plaintextElement)
                        ? plaintextElement.GetString() ?? string.Empty
                        : string.Empty;
                string body = DecodeMessageBody(plaintext);
                if (string.IsNullOrEmpty(body))
                {
                    continue;
                }

                bool outbound = direction == "outbound";
                string? deliveryStatus =
                    root.TryGetProperty("delivery_status", out JsonElement statusElement) &&
                    statusElement.ValueKind == JsonValueKind.String
                        ? statusElement.GetString()
                        : null;
                string statusLabel = deliveryStatus switch
                {
                    "read" => "Lu",
                    "delivered" => "Livré",
                    "sent" => "Envoyé",
                    "queued" => "En attente",
                    _ => "Synchronisé",
                };

                var messageContent = new StackPanel
                {
                    Spacing = 4,
                };
                messageContent.Children.Add(new TextBlock
                {
                    Text = body,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = outbound
                        ? new SolidColorBrush(Microsoft.UI.Colors.White)
                        : (Brush)Application.Current.Resources["EnigmaTextBrush"],
                });
                if (outbound)
                {
                    messageContent.Children.Add(new TextBlock
                    {
                        Text = statusLabel,
                        FontSize = 10,
                        HorizontalAlignment = HorizontalAlignment.Right,
                        Foreground = new SolidColorBrush(Microsoft.UI.Colors.White)
                        {
                            Opacity = 0.75,
                        },
                    });
                }

                var bubble = new Border
                {
                    MaxWidth = 520,
                    Padding = new Thickness(14),
                    CornerRadius = new CornerRadius(14),
                    HorizontalAlignment = outbound
                        ? HorizontalAlignment.Right
                        : HorizontalAlignment.Left,
                    Background = outbound
                        ? (Brush)Application.Current.Resources["EnigmaPrimaryBrush"]
                        : (Brush)Application.Current.Resources["EnigmaSurfaceBrush"],
                    Child = messageContent,
                };
                MessagesPanel.Children.Add(bubble);
            }
            catch (JsonException)
            {
                continue;
            }
        }

        if (MessagesPanel.Children.Count == 0)
        {
            MessagesPanel.Children.Add(new TextBlock
            {
                Text = selectedContactId is null
                    ? "Sélectionnez un contact pour afficher la conversation."
                    : "Aucun message local pour ce contact.",
                Foreground = (Brush)Application.Current.Resources["EnigmaMutedTextBrush"],
            });
        }
    }

    private async void OnRefreshClick(object sender, RoutedEventArgs args)
    {
        EnigmaCoreClient? core = _core;
        if (core is null || !core.DeviceSessionReady)
        {
            return;
        }

        RefreshButton.IsEnabled = false;
        SendButton.IsEnabled = false;
        MessageComposer.IsEnabled = false;
        ContactSelector.IsEnabled = false;
        DevicesButton.IsEnabled = false;

        try
        {
            bool outboxFlushed = await Task.Run(() => core.RetryOutbox());
            bool synchronized = await Task.Run(() => core.SyncPending());
            RefreshContacts();
            RefreshMessages();

            nuint inboxCount = core.InboxCount;
            nuint outboxCount = core.OutboxCount;
            CoreDetailText.Text = synchronized && outboxFlushed
                ? $"Synchronisation à jour • {inboxCount} message(s) local(aux)"
                : $"Synchronisation partielle • {outboxCount} livraison(s) en attente";
        }
        finally
        {
            bool ready = core.DeviceSessionReady;
            RefreshButton.IsEnabled = ready;
            SendButton.IsEnabled = ready;
            MessageComposer.IsEnabled = ready;
            ContactSelector.IsEnabled = ready;
            DevicesButton.IsEnabled = core.SignalReady;
        }
    }

    private async void OnSendClick(object sender, RoutedEventArgs args)
    {
        if (_core is null ||
            ContactSelector.SelectedItem is not ComboBoxItem selected ||
            selected.Tag is not string recipientUserId)
        {
            CoreDetailText.Text = "Choisissez un contact avant d’envoyer.";
            return;
        }

        string plaintext = MessageComposer.Text.Trim();
        if (string.IsNullOrWhiteSpace(plaintext))
        {
            return;
        }

        SendButton.IsEnabled = false;
        RefreshButton.IsEnabled = false;
        DevicesButton.IsEnabled = false;
        ContactSelector.IsEnabled = false;
        MessageComposer.IsEnabled = false;
        bool queued = await Task.Run(() => _core.SendTextToContact(recipientUserId, plaintext));
        nuint pending = _core.OutboxCount;

        if (queued)
        {
            MessageComposer.Text = string.Empty;
            RefreshMessages();
            CoreDetailText.Text = pending == 0
                ? "Message chiffré et remis à tous les appareils disponibles."
                : $"Message chiffré • {pending} livraison(s) durablement en attente.";
        }
        else
        {
            CoreDetailText.Text = "Échec de la mise en file chiffrée du message.";
        }

        MessageComposer.IsEnabled = true;
        ContactSelector.IsEnabled = true;
        SendButton.IsEnabled = true;
        RefreshButton.IsEnabled = true;
        DevicesButton.IsEnabled = _core.SignalReady;
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        _p2pPollTimer.Stop();
        _core?.Dispose();
        _core = null;
    }
}
