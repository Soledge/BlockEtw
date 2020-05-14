using System;
using System.Text;
using System.Runtime.InteropServices;

namespace Agent.PInvoke
{
    internal class Win32
    {
        internal class Kernel32
        {
            [DllImport("kernel32.dll")]
            internal static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern int GetConsoleOutputCP();

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool PeekNamedPipe(IntPtr handle, IntPtr buffer, IntPtr nBufferSize, IntPtr bytesRead, ref uint bytesAvail, IntPtr BytesLeftThisMessage);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            internal static extern void RtlZeroMemory(IntPtr pBuffer, int length);

            [DllImport("kernel32.dll")]
            internal static extern Boolean ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 dwSize, ref UInt32 lpNumberOfBytesRead);

            [DllImport("kernel32.dll")]
            internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, int flAllocationType, int flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool QueryFullProcessImageName([In]IntPtr hProcess, [In]int dwFlags, [Out]StringBuilder lpExeName, ref int lpdwSize);

            [DllImport("kernel32.dll")]
            internal static extern UInt32 ResumeThread(IntPtr hThread);

            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
        }

        internal class Ntdll
        {
            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtQueryInformationProcess(IntPtr processHandle, UInt32 processInformationClass, ref ulong processInformation, int processInformationLength, ref UInt32 returnLength);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 RtlCreateProcessParametersEx(ref IntPtr pProcessParameters, IntPtr ImagePathName, IntPtr DllPath, IntPtr CurrentDirectory, IntPtr CommandLine, IntPtr Environment, IntPtr WindowTitle, IntPtr DesktopInfo, IntPtr ShellInfo, IntPtr RuntimeData, uint Flags);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtOpenProcess(ref IntPtr ProcessHandle, UInt32 DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

            [DllImport("ntdll.dll")]
            internal static extern void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string SourceString);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 LdrGetDllHandle(
            IntPtr DllPath,
            IntPtr DllCharacteristics,
            ref UNICODE_STRING DllName,
            ref IntPtr DllHandle);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 RtlUnicodeStringToAnsiString(
            ref ANSI_STRING DestinationString,
            ref UNICODE_STRING SourceString,
            bool AllocateDestinationString);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 LdrGetProcedureAddress(
            IntPtr hModule,
            ref ANSI_STRING ModName,
            UInt32 Ordinal,
            ref IntPtr FunctionAddress);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtCreateThreadEx(
            ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr lpBytesBuffer);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtAlertResumeThread(
            IntPtr ThreadHandle,
            ref UInt32 PreviousSuspendCount);

            [DllImport("ntdll.dll")]
            internal static extern UInt32 NtQueryInformationThread(
            IntPtr ThreadHandle,
            int ThreadInformationClass,
            IntPtr ThreadInformation,
            int ThreadInformationLength,
            ref int ReturnLength);

            [DllImport("ntdll.dll")]
            public static extern UInt32 NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress);
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            internal Int32 cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal Int32 dwX;
            internal Int32 dwY;
            internal Int32 dwXSize;
            internal Int32 dwYSize;
            internal Int32 dwXCountChars;
            internal Int32 dwYCountChars;
            internal Int32 dwFillAttribute;
            internal Int32 dwFlags;
            internal Int16 wShowWindow;
            internal Int16 cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFOEX
        {
            internal STARTUPINFO StartupInfo;
            internal IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            internal IntPtr ExitStatus;
            internal IntPtr PebBaseAddress;
            internal IntPtr AffinityMask;
            internal IntPtr BasePriority;
            internal UIntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class THREAD_BASIC_INFORMATION
        {
            internal UInt32 ExitStatus;
            internal IntPtr TebBaseAddress;
            internal CLIENT_ID ClientId;
            internal UIntPtr AffinityMask;
            internal int Priority;
            internal int BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal UInt16 Length;
            internal UInt16 MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ANSI_STRING
        {
            internal UInt16 Length;
            internal UInt16 MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        internal struct OBJECT_ATTRIBUTES
        {
            internal Int32 Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CLIENT_ID
        {
            internal IntPtr UniqueProcess;
            internal IntPtr UniqueThread;
        }

        [Flags]
        internal enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        internal enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }

        [Flags]
        internal enum DuplicateOptions : uint
        {
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            DUPLICATE_SAME_ACCESS = 0x00000002
        }

        [Flags]
        internal enum AllocationProtect : uint
        {
            NONE = 0x00000000,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
    }
}