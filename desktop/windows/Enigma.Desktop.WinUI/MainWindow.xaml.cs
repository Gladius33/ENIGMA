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
            bool ready = _core.IsReady;

            CoreStatusText.Text = ready
                ? "Cœur sécurisé prêt"
                : "Cœur sécurisé indisponible";
            CoreDetailText.Text = ready
                ? $"Rust/libsignal • ABI {EnigmaCoreClient.AbiVersion}"
                : "Le cœur Rust/libsignal n’est pas prêt";

            MessageComposer.IsEnabled = ready;
            SendButton.IsEnabled = ready;
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
