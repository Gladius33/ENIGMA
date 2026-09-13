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
        if (IsInvalid) throw new InvalidOperationException("Unable to create ENIGMA core");
        if (EnigmaCoreNative.AbiVersion() != 1) throw new NotSupportedException("Unsupported ENIGMA core ABI");
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        EnigmaCoreNative.Destroy(handle);
        return true;
    }
}
