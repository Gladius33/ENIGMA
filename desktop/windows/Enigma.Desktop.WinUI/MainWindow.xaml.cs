using System;
using System.Text;
using System.Threading.Tasks;
using Enigma.Desktop.Interop;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;

namespace Enigma.Desktop.WinUI;

public sealed partial class MainWindow : Window
{
    private EnigmaCoreClient? _core;

    public MainWindow()
    {
        InitializeComponent();
        Closed += OnClosed;
        InitializeSecureCore();
    }

    private void InitializeSecureCore()
    {
        try
        {
            _core = new EnigmaCoreClient();
            bool runtimeReady = _core.IsReady;
            bool signalReady = runtimeReady &&
                (_core.SignalReady || _core.EnsureDefaultSignalIdentity());

            CoreStatusText.Text = signalReady
                ? "Cœur sécurisé prêt"
                : runtimeReady
                    ? "Identité E2EE protégée requise"
                    : "Cœur sécurisé indisponible";
            CoreDetailText.Text = signalReady
                ? $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion}"
                : runtimeReady
                    ? $"Rust chargé • ABI {EnigmaCoreClient.AbiVersion} • identité libsignal non restaurée"
                    : "Le cœur Rust n’est pas prêt";

            MessageComposer.IsEnabled = signalReady;
            SendButton.IsEnabled = signalReady;
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
        SendButton.IsEnabled = false;
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
                EnigmaPairingClaimState state = await Task.Run(() => _core.TryClaimPairing());
                switch (state)
                {
                    case EnigmaPairingClaimState.Claimed:
                        pairingStatus.Text = "Ordinateur lié avec succès.";
                        CoreStatusText.Text = "Cœur sécurisé prêt • appareil lié";
                        dialog.Hide();
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

    private void OnClosed(object sender, WindowEventArgs args)
    {
        _core?.Dispose();
        _core = null;
    }
}
