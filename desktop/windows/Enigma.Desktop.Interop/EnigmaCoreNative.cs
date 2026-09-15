using System;
using System.Runtime.InteropServices;

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
