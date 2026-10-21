param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [string]$Root = (Join-Path $env:TEMP ('kmx-windows-offline-' + [Guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Binary).ProviderPath
if (Test-Path -LiteralPath $Root) { throw 'Offline qualification requires a fresh root; existing state is never adopted.' }
$oldHome = [Environment]::GetEnvironmentVariable('KMX_HOME', 'Process')
function Invoke-Kmx([string[]]$CommandArgs) {
    & $exe @CommandArgs
    if ($LASTEXITCODE -ne 0) { throw "kmx offline qualification failed ($LASTEXITCODE): $($CommandArgs[0])" }
}
try {
    New-Item -ItemType Directory -Path $Root | Out-Null
    $env:KMX_HOME = Join-Path $Root 'state'
    $instructions = Join-Path $Root 'instructions.md'
    [IO.File]::WriteAllText($instructions, "Reply with a short greeting.`n", (New-Object System.Text.UTF8Encoding $false))
    $workspace = Join-Path $Root 'workspace'
    $layout = Join-Path $Root 'layout'
    $pulled = Join-Path $Root 'pulled'
    Invoke-Kmx -CommandArgs @('version')
    Invoke-Kmx -CommandArgs @('--help')
    Invoke-Kmx -CommandArgs @('create', 'greeter', '--workspace', $workspace, '--model', 'fixture-model', '--instructions', $instructions)
    Invoke-Kmx -CommandArgs @('push', '--workspace', $workspace, '--unevaluated', '--to-layout', $layout, 'agentsuites/greeter:v1')
    Invoke-Kmx -CommandArgs @('suite', 'pull', 'agentsuites/greeter:v1', '--from-layout', $layout, '--output', $pulled)
    Invoke-Kmx -CommandArgs @('suite', 'validate', $pulled)
    Write-Output "Native offline authoring/storage qualification passed. Artifacts retained: $Root"
} finally {
    [Environment]::SetEnvironmentVariable('KMX_HOME', $oldHome, 'Process')
}
