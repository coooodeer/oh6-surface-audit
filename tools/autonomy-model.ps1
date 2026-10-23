param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('show', 'configure', 'use', 'set-key', 'remove-key', 'validate-key', 'probe', 'run')]
    [string]$Action,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Options,
    [securestring]$Secret
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'windows-native-required'
}

$backend = Join-Path $PSScriptRoot 'autonomy-model-manager.js'
if ($Action -ne 'set-key') {
    & node $backend $Action @Options
    exit $LASTEXITCODE
}

if ($Options.Count -gt 0) { throw 'set-key has no command-line secret option' }
if (-not $Secret) { $Secret = Read-Host 'Provider API key' -AsSecureString }
if (-not $Secret -or $Secret.Length -eq 0) { throw 'empty-key' }

$previous = [Environment]::GetEnvironmentVariable('OH6_LLM_API_KEY', 'Process')
$pointer = [IntPtr]::Zero
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    $env:OH6_LLM_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    & node $backend store-key
    $code = $LASTEXITCODE
} finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    [Environment]::SetEnvironmentVariable('OH6_LLM_API_KEY', $previous, 'Process')
}
exit $code
