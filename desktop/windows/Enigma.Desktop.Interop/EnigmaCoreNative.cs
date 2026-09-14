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
