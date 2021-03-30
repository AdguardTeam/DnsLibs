# Windows test application

Steps to run:
1) Build dnslibs: run the following commands in `x86 Native Tools` terminal

    ```bash
    cd dns-libs\platform\windows\capi
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -G "Ninja" ..
    ninja AdguardDns
    ```

2) Open `Adguard.Dns.sln` in the IDE (VS or JBRider) and build it, using `TestAppRelease|AnyCPU` configuration. Also you can use `x86 Native Tools` terminal, run as Administrator beforehand, instead of IDE
Run the following command from the terminal:

    ```bash
    cd dns-libs\platform\windows\cs\Adguard.Dns
    msbuild Adguard.Dns.sln /t:Build /p:Configuration=TestAppRelease /p:Platform="Any CPU"
    ```

IMPORTANT: all the projects in the solution (Adguard.Dns.sln) are delay signed with the strong name. In order to start them (in particular Adguard.Dns.TestApp.exe) you have either sign them with the private strong name key (file like adguard.pfx) after building or disable verifying strong name signature for all the binaries. The easiest way is the second option. To do so you have to run following commands in the x86 Native Tools terminal, run as Administrator beforehand:

```bash
cd dns-libs\platform\windows\cs\Adguard.Dns\build\bin\TestAppRelease
sn –Vr Adguard.Dns.TestApp.exe
sn –Vr Adguard.Dns.dll
```

See more on [docs.microsoft.com](https://docs.microsoft.com/en-us/dotnet/standard/assembly/delay-sign)
Note, that if you disable verifying strong name signature only once, you haven't do this every time you build, you can just forget about this.

3) Start the test app.
If you are using any IDE (VS ot JB Rider) run `Adguard.Dns.TestApp.exe`. If you has built the solution from the console, run following command:

    ```bash
    cd dns-libs\platform\windows\cs\Adguard.Dns\build\bin\TestAppRelease
    Adguard.Dns.TestApp.exe
    ```

4) If you want to grab log into the file (instead of console) you should uncomment (or comment it to force output to console) directive `#define LOG_TO_FILE` in the "header" (`dns-libs\platform\windows\cs\Adguard.Dns\Adguard.Dns.Testapp\Program.cs`) of file and start from the 2nd point.