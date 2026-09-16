using System;
using System.Globalization;\nusing System.IO;\nusing System.Text;
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
        string iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "enigma.ico");
        if (File.Exists(iconPath))
        {
            AppWindow.SetIcon(iconPath);
        }

        LanguageSelector.SelectedIndex = _language == DesktopLanguage.French ? 0 : 1;
        LanguageSelector.SelectionChanged += OnLanguageSelectionChanged;
        Closed += OnClosed;
        ContactSelector.SelectionChanged += OnContactSelectionChanged;
        _p2pPollTimer.Interval = TimeSpan.FromMilliseconds(750);
        _p2pPollTimer.Tick += OnP2pPollTick;
        ApplyStaticLanguage();
        InitializeSecureCore();
    }

    private string T(string key) => DesktopStrings.Get(key, _language);

    private string F(string key, params object[] args) =>
        string.Format(CultureInfo.CurrentCulture, T(key), args);

    private void ApplyStaticLanguage()
    {
        BrandSubtitleText.Text = T("brand.subtitle");
        DeviceSectionText.Text = T("device.section");
        DeviceSessionText.Text = T("device.session");
        HeaderTitleText.Text = T("header.title");
        HeaderSubtitleText.Text = T("header.subtitle");
        RefreshButton.Content = T("refresh");
        DevicesButton.Content = _core?.DeviceSessionReady == true
            ? T("devices.manage")
            : T("devices.pair");
        CryptoNoticeText.Text = T("crypto.notice");
        ContactSelector.PlaceholderText = T("contact.choose");
        MessageComposer.PlaceholderText = T("message.placeholder");
        SendButton.Content = T("send");
    }

    private void OnLanguageSelectionChanged(object sender, SelectionChangedEventArgs args)
    {
        if (LanguageSelector.SelectedItem is not ComboBoxItem item || item.Tag is not string code)
        {
            return;
        }
        DesktopLanguage next = DesktopStrings.FromCode(code);
        if (next == _language)
        {
            return;
        }
        _language = next;
        DesktopStrings.SaveLanguage(_language);
        ApplyStaticLanguage();
        RelocalizeCoreState();
        RefreshMessages();
    }

    private void RelocalizeCoreState()
    {
        if (_core is null)
        {
            CoreStatusText.Text = T("status.initializing");
            CoreDetailText.Text = T("detail.core_not_ready");
            return;
        }

        bool runtimeReady = _core.IsReady;
        bool signalReady = runtimeReady && _core.SignalReady;
        bool sessionReady = signalReady && _core.DeviceSessionReady;
        if (sessionReady && _p2pPollTimer.IsEnabled)
        {
            CoreStatusText.Text = T("status.ready");
            CoreDetailText.Text = F("detail.ready", EnigmaCoreClient.AbiVersion, _core.InboxCount);
        }
        else if (signalReady && sessionReady)
        {
            CoreStatusText.Text = T("status.session_network");
            CoreDetailText.Text = T("detail.session_retry");
        }
        else if (signalReady)
        {
            CoreStatusText.Text = T("status.pair_required");
            CoreDetailText.Text = T("detail.pair_hint");
        }
        else if (runtimeReady)
        {
            CoreStatusText.Text = T("status.identity_required");
            CoreDetailText.Text = F("detail.identity_missing", EnigmaCoreClient.AbiVersion);
        }
        else
        {
            CoreStatusText.Text = T("status.unavailable");
            CoreDetailText.Text = T("detail.core_not_ready");
        }
        ApplyStaticLanguage();
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
                ? T("status.ready")
                : signalReady
                    ? sessionReady
                        ? T("status.session_network")
                        : T("status.pair_required")
                    : runtimeReady
                        ? T("status.identity_required")
                        : T("status.unavailable");
            CoreDetailText.Text = operationalReady
                ? inboxSynced && outboxFlushed
                    ? F("detail.ready", EnigmaCoreClient.AbiVersion, inboxCount)
                    : F("detail.pending", EnigmaCoreClient.AbiVersion, outboxCount)
                : signalReady
                    ? sessionReady
                        ? T("detail.session_retry")
                        : T("detail.pair_hint")
                    : runtimeReady
                        ? F("detail.identity_missing", EnigmaCoreClient.AbiVersion)
                        : T("detail.core_not_ready");

            MessageComposer.IsEnabled = operationalReady;
            ContactSelector.IsEnabled = operationalReady;
            SendButton.IsEnabled = operationalReady;
            RefreshButton.IsEnabled = operationalReady;
            DevicesButton.IsEnabled = signalReady;
            DevicesButton.Content = sessionReady ? T("devices.manage") : T("devices.pair");
            if (operationalReady)
            {
                RefreshContacts();
                RefreshMessages();
                _p2pPollTimer.Start();
            }
        }
        catch (DllNotFoundException)
        {
            SetCoreUnavailable(T("core.native_missing"));
        }
        catch (BadImageFormatException)
        {
            SetCoreUnavailable(T("core.native_incompatible"));
        }
        catch (NotSupportedException)
        {
            SetCoreUnavailable(T("core.abi_incompatible"));
        }
        catch (InvalidOperationException)
        {
            SetCoreUnavailable(T("core.init_failed"));
        }
    }

    private void SetCoreUnavailable(string detail)
    {
        CoreStatusText.Text = T("status.unavailable");
        CoreDetailText.Text = detail;
        DevicesButton.Content = T("devices.pair");
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
                    F("p2p.received", after);
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
            SetCoreUnavailable(T("pair.create_failed"));
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
                throw new InvalidOperationException(T("pair.create_failed"));
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
                Text = T("pair.scan"),
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
                Text = F("pair.expires", expiresAt.ToString("HH:mm:ss", CultureInfo.CurrentCulture)),
                Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["EnigmaMutedTextBrush"],
            });
            panel.Children.Add(new TextBox
            {
                Header = T("pair.uri"),
                Text = pairing.Uri,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
            });

            var pairingStatus = new TextBlock
            {
                Text = T("pair.wait"),
                TextWrapping = TextWrapping.Wrap,
            };
            var finalizeButton = new Button
            {
                Content = T("pair.finalize"),
                HorizontalAlignment = HorizontalAlignment.Left,
            };
            panel.Children.Add(pairingStatus);
            panel.Children.Add(finalizeButton);

            var dialog = new ContentDialog
            {
                XamlRoot = DevicesButton.XamlRoot,
                Title = T("pair.title"),
                Content = panel,
                CloseButtonText = T("pair.close"),
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
                        pairingStatus.Text = T("pair.authorized_keys");
                        bool initialized = await Task.Run(() => _core.InitializeDevice());
                        if (initialized)
                        {
                            pairingStatus.Text = "Ordinateur lié avec succès.";
                            CoreStatusText.Text = T("status.ready");
                            bool outboxFlushed = await Task.Run(() => _core.RetryOutbox());
                            bool synchronized = await Task.Run(() => _core.SyncPending());
                            nuint inboxCount = _core.InboxCount;
                            nuint outboxCount = _core.OutboxCount;
                            CoreDetailText.Text = synchronized && outboxFlushed
                                ? F("detail.ready", EnigmaCoreClient.AbiVersion, inboxCount)
                                : F("detail.pending", EnigmaCoreClient.AbiVersion, outboxCount);
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
                                T("pair.init_failed");
                            finalizeButton.Content = T("pair.retry_init");
                            finalizeButton.IsEnabled = true;
                        }
                        break;
                    case EnigmaPairingClaimState.PendingAuthorization:
                        pairingStatus.Text = T("pair.authorize_first");
                        finalizeButton.IsEnabled = true;
                        break;
                    case EnigmaPairingClaimState.Expired:
                        pairingStatus.Text = T("pair.expired");
                        break;
                    case EnigmaPairingClaimState.AlreadyClaimed:
                        pairingStatus.Text = T("pair.used");
                        break;
                    case EnigmaPairingClaimState.Missing:
                        pairingStatus.Text = T("pair.missing");
                        break;
                    default:
                        pairingStatus.Text = T("pair.server_unavailable");
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
                Title = T("pair.fallback_title"),
                Content = pairing.Uri,
                CloseButtonText = T("pair.close"),
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
            CoreDetailText.Text = T("contacts.invalid");
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
                    "read" => T("message.read"),
                    "delivered" => T("message.delivered"),
                    "sent" => T("message.sent"),
                    "queued" => T("message.queued"),
                    _ => T("message.synced"),
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
                    ? T("message.select_contact")
                     : T("message.none"),
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
                ? F("sync.ready", inboxCount)
                : F("sync.partial", outboxCount);
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
            CoreDetailText.Text = T("send.choose_contact");
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
                ? T("send.delivered")
                : F("send.pending", pending);
        }
        else
        {
            CoreDetailText.Text = T("send.failed");
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
