<#
.SYNOPSIS
    Windows (PowerShell 5.1) port of scripts/set_version.sh.

    Stamps the project version across the platform-specific source files that
    are compiled into the build. Pass a version explicitly, or omit it to derive
    one from `git describe` (the default for local builds). Mirrors
    set_version.sh field-for-field so the two are interchangeable on their
    respective runners.

    The numeric core "X.Y.Z" is written to the fields that accept numbers only
    (the Apple framework CMake VERSION, the Windows FILEVERSION/PRODUCTVERSION
    and the .NET AssemblyVersion/AssemblyFileVersion); the full version string is
    written to every free-form field (the Gradle version name, the Windows
    ProductVersion display string and AssemblyInformationalVersion, and the C++
    AG_DNSLIBS_VERSION macro).
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$NewVersion,

    # Anything beyond the single optional version is an error, matching the
    # shell script's "Usage" guard.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = 'Stop'

if ($Rest -and $Rest.Count -gt 0) {
    Write-Error "Usage: set_version.ps1 [version]"
    exit 1
}

# Repo root is the script's parent directory (scripts/..).
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Read whole-file text and write it back unchanged except for the replacement,
# preserving line endings and avoiding a BOM (matches sed's byte behaviour).
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Set-Version-InFile {
    param([string]$RelPath, [string]$Pattern, [string]$Replacement)
    $path = Join-Path $root $RelPath
    $text = [System.IO.File]::ReadAllText($path)
    # MatchEvaluator returns the replacement literally, so '$' in versions is
    # never treated as a regex substitution token.
    $eval = [System.Text.RegularExpressions.MatchEvaluator] { param($m) $Replacement }
    $new = [regex]::Replace($text, $Pattern, $eval)
    [System.IO.File]::WriteAllText($path, $new, $utf8NoBom)
}

# Resolve the new version: an explicit argument wins; otherwise derive it from
# the nearest version tag via git describe (matching set_version.sh).
if (-not [string]::IsNullOrEmpty($NewVersion)) {
    $new_full = $NewVersion
} else {
    $new_full = (& git describe --tags --match 'v*') -replace '^v', ''
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($new_full)) {
        Write-Error "git describe failed to resolve a version"
        exit 1
    }
}

# Free-form full string and numeric core (everything before the first - or +):
# both "1.2.3-rc.1" and "1.2.3-6-gabcdef" -> core "1.2.3".
$new_core = $new_full -replace '[-+].*$', ''

if ($new_full -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$') {
    Write-Error "Invalid version format: $new_full"
    exit 1
}
if ($new_core -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    Write-Error "Invalid version core: $new_core"
    exit 1
}

$gradleRel = 'platform/android/dnsproxy/lib/build.gradle'
$gradleLine = (Select-String -Path (Join-Path $root $gradleRel) -Pattern '^version =' |
    Select-Object -First 1).Line

# Current full version and its core, parsed from the Gradle version name. Same
# pipeline as the shell script: drop everything from the first comma, then up to
# the last colon, then strip quotes and spaces.
$current_full = $gradleLine -replace ',.*', '' -replace '.*:', '' -replace "[' ]", ''
if ([string]::IsNullOrEmpty($current_full)) {
    Write-Error "Failed to detect current version from $gradleRel"
    exit 1
}
$current_core = $current_full -replace '[-+].*$', ''
Write-Host "Version: $current_full -> $new_full (core $current_core -> $new_core)"

# Android version code: bump by one.
$current_code = [int]([regex]::Match($gradleLine, 'code:\s*(\d+)').Groups[1].Value)
$new_code = $current_code + 1

# Escaped search patterns: "esc" matches the old full version (free-string
# fields), "esc_core" matches the old numeric core (core-only fields).
$esc = [regex]::Escape($current_full)
$esc_core = [regex]::Escape($current_core)

# Android Gradle: version name (free string) and version code.
Set-Version-InFile $gradleRel "name: '$esc'" "name: '$new_full'"
Set-Version-InFile $gradleRel "code: $current_code" "code: $new_code"

# Apple framework CMake VERSION (numeric core only).
Set-Version-InFile 'platform/mac/framework/CMakeLists.txt' "    VERSION $esc_core" "    VERSION $new_core"

# Windows resource versions: FILEVERSION/PRODUCTVERSION are numeric (commas);
# the ProductVersion string is free-form.
$old_commas = $current_core -replace '\.', ','
$new_commas = $new_core -replace '\.', ','
$rcRel = 'platform/windows/capi/src/ag_dns.rc'
Set-Version-InFile $rcRel "FILEVERSION $old_commas,0" "FILEVERSION $new_commas,0"
Set-Version-InFile $rcRel "PRODUCTVERSION $old_commas,0" "PRODUCTVERSION $new_commas,0"
Set-Version-InFile $rcRel "`"ProductVersion`", `"$esc`"" "`"ProductVersion`", `"$new_full`""

# .NET assembly versions: AssemblyVersion/AssemblyFileVersion are numeric
# (core); AssemblyInformationalVersion is free-form and carries the full version
# (it feeds the NuGet package's $version$ token). Match its value with a
# wildcard so the replacement is robust regardless of the current contents.
$csRel = 'platform/windows/cs/Adguard.Dns/SolutionInfo.cs'
Set-Version-InFile $csRel "AssemblyVersion\(`"$esc_core`"\)" "AssemblyVersion(`"$new_core`")"
Set-Version-InFile $csRel "AssemblyFileVersion\(`"$esc_core`"\)" "AssemblyFileVersion(`"$new_core`")"
Set-Version-InFile $csRel 'AssemblyInformationalVersion\("[^"]*"\)' "AssemblyInformationalVersion(`"$new_full`")"

# C++ library version string (free string, full version). Matched with a
# wildcard so it works regardless of the current placeholder value.
Set-Version-InFile 'common/include/dns/common/version.h' '#define AG_DNSLIBS_VERSION "[^"]*"' "#define AG_DNSLIBS_VERSION `"$new_full`""

Write-Host "Version updated: $new_full (core $new_core)"
