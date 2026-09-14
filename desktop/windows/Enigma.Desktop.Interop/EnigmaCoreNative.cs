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

    [LibraryImport(LibraryName, EntryPoint = "enigma_core_signal_initialize")]
    [return: MarshalAs(UnmanagedType.I1)]
    internal static unsafe partial bool SignalInitialize(
        IntPtr handle,
        byte* serializedIdentity,
        nuint serializedIdentityLength,
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

    internal unsafe bool InitializeSignalIdentity(ReadOnlySpan<byte> serializedIdentity, uint registrationId)
    {
        if (serializedIdentity.IsEmpty)
        {
            return false;
        }

        fixed (byte* identity = serializedIdentity)
        {
            return EnigmaCoreNative.SignalInitialize(
                handle,
                identity,
                checked((nuint)serializedIdentity.Length),
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
/// Cryptographic operations remain implemented by the Rust/libsignal backend.
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
    /// Restores the canonical libsignal identity previously read from protected local storage.
    /// The serialized representation is validated inside the pinned Rust/libsignal backend.
    /// </summary>
    public unsafe bool InitializeSignalIdentity(
        ReadOnlySpan<byte> serializedIdentity,
        uint registrationId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _handle.InitializeSignalIdentity(serializedIdentity, registrationId);
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
