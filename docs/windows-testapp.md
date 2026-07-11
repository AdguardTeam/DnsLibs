# Windows test application

This document describes how to build and run the Windows C# test application located in
`platform/windows/cs/Adguard.Dns`.

## Build the native DLL

Open the **x86 Native Tools** terminal and run:

```batch
cd dns-libs\platform\windows\capi
if exist build rmdir /s /q build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G "Ninja" ..
ninja AdguardDns
```

For 64-bit builds, use `vcvars64` and `ninja AdguardDns64`.

The CMake post-build step copies the native DLLs to `platform/windows/cs/Adguard.Dns/Adguard.Dns/x86/` (or `x64/`,
`Arm64/`). The C# projects expect the DLLs to be present there before the managed build starts.

## Build the C# solution

### With an IDE

1. Open `platform/windows/cs/Adguard.Dns/Adguard.Dns.sln` in Visual Studio or JetBrains Rider.
2. Restore NuGet packages (e.g., `nuget restore Adguard.Dns.sln` if using the command line).
3. Build the `TestAppRelease|Any CPU` configuration.

### From the command line

Open the **x86 Native Tools** terminal and run:

```batch
cd dns-libs\platform\windows\cs\Adguard.Dns
nuget restore Adguard.Dns.sln
msbuild Adguard.Dns.sln /t:Build /p:Configuration=TestAppRelease /p:Platform="Any CPU"
```

> Building the solution itself does not require Administrator privileges; elevation is only needed for the strong-name
> verification skip described below.

## Strong-name signing

All projects in the solution are delay-signed with a strong name using the public key file `adguard.snk`. To run the
test application (`Adguard.Dns.TestApp.exe`) you must either sign the binaries with the private counterpart of the
strong-name key pair or disable strong-name verification for the relevant assemblies.

The easiest approach is to disable verification. Open the **x86 Native Tools** terminal **as Administrator** and run:

```batch
cd dns-libs\platform\windows\cs\Adguard.Dns\build\bin\TestAppRelease
sn -Vr Adguard.Dns.TestApp.exe
sn -Vr Adguard.Dns.dll
```

See the [Microsoft documentation](https://docs.microsoft.com/en-us/dotnet/standard/assembly/delay-sign) for more
details. Disabling verification only needs to be done once per machine.

## Run the test app

### From the IDE

Run `Adguard.Dns.TestApp.exe` from the project start-up settings.

### From the command line

```batch
cd dns-libs\platform\windows\cs\Adguard.Dns\build\bin\TestAppRelease
Adguard.Dns.TestApp.exe
```

The post-build script also copies artifacts into `build\bin\TestAppRelease\DnsLibs\`.

## Logging

To write logs to a file instead of the console, uncomment the `#define LOG_TO_FILE` directive at the top of
`dns-libs/platform/windows/cs/Adguard.Dns/Adguard.Dns.TestApp/Program.cs` and rebuild. When enabled, log files are
written to a `Logs` subdirectory in the application base directory.
