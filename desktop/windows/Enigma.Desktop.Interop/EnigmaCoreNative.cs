using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Enigma.Desktop.Interop;

internal static partial class EnigmaCoreNative
{
    private const string LibraryName = "enigma_core";

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_abi_version")]
    internal static partial uint AbiVersion();

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_create")]
    internal static partial IntPtr Create();

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_destroy")]
    internal static partial void Destroy(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_is_ready")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool IsReady(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_signal_is_ready")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool SignalIsReady(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_signal_load_or_create_default")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool SignalLoadOrCreateDefault(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_signal_initialize_protected")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static unsafe partial bool SignalInitializeProtected(
        IntPtr handle,
        byte* protectedIdentity,
        nuint protectedIdentityLength,
        uint registrationId);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_start")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool PairingStart(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_publish")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool PairingPublish(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_claim")]
    internal static partial uint PairingClaim(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_device_session_ready")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static partial bool DeviceSessionReady(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_cancel")]
    internal static partial void PairingCancel(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_uri_len")]
    internal static partial nuint PairingUriLength(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_uri_copy")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static unsafe partial bool PairingUriCopy(IntPtr handle, byte* output, nuint outputLength);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_svg_len")]
    internal static partial nuint PairingSvgLength(IntPtr handle);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_svg_copy")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static unsafe partial bool PairingSvgCopy(IntPtr handle, byte* output, nuint outputLength);

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_pairing_expires_at_unix_ms")]
    internal static partial ulong PairingExpiresAtUnixMs(IntPtr handle);
}

internal sealed class EnigmaCoreHandle : SafeHandle
{
    internal EnigmaCoreHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(EnigmaCoreNative.Create());
        if (IsInvalid)
        {
            throw new InvalidOperationException("Unable to create ENIGMA core");
        }

        if (EnigmaCoreNative.AbiVersion() != 1)
        {
            throw new NotSupportedException("Unsupported ENIGMA core ABI");
        }
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    internal bool IsReady => EnigmaCoreNative.IsReady(handle);

    internal bool SignalIsReady => EnigmaCoreNative.SignalIsReady(handle);

    internal bool EnsureDefaultSignalIdentity() =>
        EnigmaCoreNative.SignalLoadOrCreateDefault(handle);

    internal unsafe bool InitializeProtectedSignalIdentity(
        ReadOnlySpan<byte> protectedIdentity,
        uint registrationId)
    {
        if (protectedIdentity.IsEmpty)
        {
            return false;
        }

        fixed (byte* identity = protectedIdentity)
        {
            return EnigmaCoreNative.SignalInitializeProtected(
                handle,
                identity,
                checked((nuint)protectedIdentity.Length),
                registrationId);
        }
    }

    internal bool StartPairing() => EnigmaCoreNative.PairingStart(handle);

    internal bool PublishPairing() => EnigmaCoreNative.PairingPublish(handle);

    internal uint ClaimPairing() => EnigmaCoreNative.PairingClaim(handle);

    internal bool DeviceSessionReady => EnigmaCoreNative.DeviceSessionReady(handle);

    internal void CancelPairing() => EnigmaCoreNative.PairingCancel(handle);

    internal unsafe string ReadPairingUri()
    {
        nuint length = EnigmaCoreNative.PairingUriLength(handle);
        if (length == 0 || length > int.MaxValue)
        {
            return string.Empty;
        }

        byte[] bytes = new byte[(int)length];
        fixed (byte* output = bytes)
        {
            if (!EnigmaCoreNative.PairingUriCopy(handle, output, length))
            {
                return string.Empty;
            }
        }
        return Encoding.UTF8.GetString(bytes);
    }

    internal unsafe string ReadPairingSvg()
    {
        nuint length = EnigmaCoreNative.PairingSvgLength(handle);
        if (length == 0 || length > int.MaxValue)
        {
            return string.Empty;
        }

        byte[] bytes = new byte[(int)length];
        fixed (byte* output = bytes)
        {
            if (!EnigmaCoreNative.PairingSvgCopy(handle, output, length))
            {
                return string.Empty;
            }
        }
        return Encoding.UTF8.GetString(bytes);
    }

    internal ulong PairingExpiresAtUnixMs => EnigmaCoreNative.PairingExpiresAtUnixMs(handle);

    protected override bool ReleaseHandle()
    {
        EnigmaCoreNative.Destroy(handle);
        return true;
    }
}

/// <summary>
/// Managed lifetime boundary for the shared Rust ENIGMA core.
/// Cryptographic operations and protected-identity restoration remain inside Rust.
/// </summary>
public enum EnigmaPairingClaimState : uint
{
    Error = 0,
    PendingAuthorization = 1,
    Claimed = 2,
    AlreadyClaimed = 3,
    Expired = 4,
    Missing = 5,
}

public sealed record EnigmaPairingBootstrap(
    string Uri,
    string Svg,
    ulong ExpiresAtUnixMs);

public sealed class EnigmaCoreClient : IDisposable
{
    private readonly EnigmaCoreHandle _handle = new();
    private bool _disposed;

    public static uint AbiVersion => EnigmaCoreNative.AbiVersion();

    public bool IsReady
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle.IsReady;
        }
    }

    public bool SignalReady
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle.SignalIsReady;
        }
    }

    /// <summary>
    /// Restores the platform-protected Signal identity or provisions it on first launch.
    /// The private identity remains inside Rust and the native OS protection backend.
    /// </summary>
    public bool EnsureDefaultSignalIdentity()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _handle.EnsureDefaultSignalIdentity();
    }

    /// <summary>
    /// Restores Signal from an OS-protected blob/locator. Plaintext private-key
    /// material never crosses the managed UI boundary.
    /// </summary>
    public unsafe bool InitializeProtectedSignalIdentity(
        ReadOnlySpan<byte> protectedIdentity,
        uint registrationId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _handle.InitializeProtectedSignalIdentity(protectedIdentity, registrationId);
    }

    public EnigmaPairingBootstrap? StartPairing()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_handle.SignalIsReady || !_handle.StartPairing())
        {
            return null;
        }
        if (!_handle.PublishPairing())
        {
            _handle.CancelPairing();
            return null;
        }

        string uri = _handle.ReadPairingUri();
        string svg = _handle.ReadPairingSvg();
        ulong expiresAtUnixMs = _handle.PairingExpiresAtUnixMs;
        if (string.IsNullOrWhiteSpace(uri) || string.IsNullOrWhiteSpace(svg) || expiresAtUnixMs == 0)
        {
            _handle.CancelPairing();
            return null;
        }

        return new EnigmaPairingBootstrap(uri, svg, expiresAtUnixMs);
    }

    public EnigmaPairingClaimState TryClaimPairing()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (EnigmaPairingClaimState)_handle.ClaimPairing();
    }

    public bool DeviceSessionReady
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle.DeviceSessionReady;
        }
    }

    public void CancelPairing()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _handle.CancelPairing();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _handle.Dispose();
        _disposed = true;
    }
}
