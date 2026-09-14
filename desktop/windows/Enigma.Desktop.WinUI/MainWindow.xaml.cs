using System;
using Enigma.Desktop.Interop;
using Microsoft.UI.Xaml;

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
            bool signalReady = runtimeReady && _core.SignalReady;

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

    private void OnClosed(object sender, WindowEventArgs args)
    {
        _core?.Dispose();
        _core = null;
    }
}
