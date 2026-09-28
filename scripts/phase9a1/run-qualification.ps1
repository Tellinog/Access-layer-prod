[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$runId = ([Guid]::NewGuid().ToString('N')).Substring(0, 12)
$databaseUser = 'phase9a1_qualifier'
$passwordBytes = [byte[]]::new(24)
$passwordGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
$passwordGenerator.GetBytes($passwordBytes)
$passwordGenerator.Dispose()
$databasePassword = -join ($passwordBytes | ForEach-Object { $_.ToString('x2') })
$started = [System.Collections.Generic.List[string]]::new()
$oldRoot = Join-Path $repoRoot "tmp\phase9a1-old-$runId"
$oldArchive = Join-Path $repoRoot "tmp\phase9a1-old-$runId.zip"

function Assert-SyntheticName([string]$name) {
  if ($name -notmatch '^access-layer-phase9a1-(source|restore|compat)-[a-f0-9]{12}$') {
    throw 'Unsafe disposable PostgreSQL container name'
  }
}

function Start-Postgres([string]$kind) {
  $name = "access-layer-phase9a1-$kind-$runId"
  $database = "access_layer_phase9a1_${kind}_test_$runId"
  Assert-SyntheticName $name
  if ($database -notmatch '^access_layer_phase9a1_(source|restore|compat)_test_[a-f0-9]{12}$') {
    throw 'Unsafe disposable PostgreSQL database name'
  }
  & docker run --detach --rm --name $name --label 'access-layer.qualifier=phase9a1' `
    --publish '127.0.0.1::5432' `
    --env "POSTGRES_USER=$databaseUser" `
    --env "POSTGRES_PASSWORD=$databasePassword" `
    --env "POSTGRES_DB=$database" postgres:16 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start disposable PostgreSQL 16' }
  $started.Add($name)
  $ready = $false
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & docker exec $name pg_isready --quiet --username $databaseUser --dbname $database
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) { throw 'Disposable PostgreSQL did not become ready' }
  $binding = (& docker port $name 5432/tcp).Trim()
  if ($LASTEXITCODE -ne 0 -or $binding -notmatch '^127\.0\.0\.1:(\d+)$') {
    throw 'PostgreSQL must publish on loopback only'
  }
  return "postgresql://${databaseUser}:${databasePassword}@127.0.0.1:$($Matches[1])/${database}"
}

try {
  if ($env:DOCKER_HOST) { throw 'Remote Docker host is forbidden' }
  $context = (& docker context show).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Docker context unavailable' }
  $endpoint = (& docker context inspect $context --format '{{.Endpoints.docker.Host}}').Trim()
  if ($LASTEXITCODE -ne 0 -or $endpoint -notmatch '^npipe:') {
    throw 'Phase 9A.1 qualification requires the local Windows Docker daemon'
  }
  $serverType = (& docker info --format '{{.OSType}}').Trim()
  if ($LASTEXITCODE -ne 0 -or $serverType -ne 'linux') { throw 'Linux Docker engine required' }

  $sourceUrl = Start-Postgres 'source'
  $restoreUrl = Start-Postgres 'restore'
  $compatUrl = Start-Postgres 'compat'
  $env:PHASE9A1_SOURCE_DATABASE_URL = $sourceUrl
  $env:PHASE9A1_RESTORE_DATABASE_URL = $restoreUrl
  $env:PHASE9A1_COMPAT_DATABASE_URL = $compatUrl

  Push-Location $repoRoot
  try {
    foreach ($url in @($sourceUrl, $restoreUrl, $compatUrl)) {
      $env:DATABASE_URL = $url
      & npm.cmd run migrate --silent
      if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL migrations failed' }
    }
    Remove-Item Env:DATABASE_URL
    $env:OAUTH_NATIVE_DISPOSABLE_PG_URL = $sourceUrl
    $env:OAUTH_NATIVE_DISPOSABLE_PG_CONFIRM = 'yes'
    & npm.cmd test -- tests/oauth-native-postgres.test.ts
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL foundation assertions failed' }
    & (Join-Path $repoRoot 'node_modules\.bin\tsx.cmd') (Join-Path $PSScriptRoot 'qualify.ts')
    if ($LASTEXITCODE -ne 0) { throw 'Encrypted backup qualification failed' }

    $qualifiedCommit = (& git rev-parse HEAD).Trim()
    $baseline = '691f248339c445bbf7207c7af91c63e42472347b'
    if ($LASTEXITCODE -ne 0 -or $qualifiedCommit -notmatch '^[a-f0-9]{40}$') {
      throw 'Qualification commit unavailable'
    }
    & git merge-base --is-ancestor $baseline $qualifiedCommit
    if ($LASTEXITCODE -ne 0) { throw 'Previous-binary baseline is not an ancestor' }
    New-Item -ItemType Directory -Path $oldRoot -Force | Out-Null
    & git archive --format=zip --output=$oldArchive $baseline
    if ($LASTEXITCODE -ne 0) { throw 'Previous-binary archive failed' }
    Expand-Archive -LiteralPath $oldArchive -DestinationPath $oldRoot -Force
    & (Join-Path $repoRoot 'node_modules\.bin\tsc.cmd') -p (Join-Path $oldRoot 'tsconfig.json')
    if ($LASTEXITCODE -ne 0) { throw 'Previous-binary build failed' }
    $env:PHASE9A1_OLD_DIST_ROOT = Join-Path $oldRoot 'dist'
    & node (Join-Path $PSScriptRoot 'old-binary-smoke.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Previous-binary compatibility smoke failed' }

    $migrationHash = (Get-FileHash -LiteralPath (Join-Path $repoRoot 'migrations\006_oauth_native_entitlements_dark.sql') -Algorithm SHA256).Hash.ToLowerInvariant()
    $imageId = (& docker image inspect postgres:16 --format '{{.Id}}').Trim()
    Write-Output (ConvertTo-Json -Compress @{
      qualification = 'phase9a1-disposable-postgresql'
      qualified_commit = $qualifiedCommit
      baseline_commit = $baseline
      migration_006_sha256 = $migrationHash
      postgres_image = $imageId
      targets = 3
      loopback_only = $true
      production_contacted = $false
      outcome = 'passed'
    })
  } finally {
    Pop-Location
  }
} finally {
  foreach ($key in @('DATABASE_URL', 'PHASE9A1_SOURCE_DATABASE_URL', 'PHASE9A1_RESTORE_DATABASE_URL',
      'PHASE9A1_COMPAT_DATABASE_URL', 'PHASE9A1_OLD_DIST_ROOT', 'OAUTH_NATIVE_DISPOSABLE_PG_URL',
      'OAUTH_NATIVE_DISPOSABLE_PG_CONFIRM')) {
    Remove-Item "Env:$key" -ErrorAction SilentlyContinue
  }
  foreach ($name in $started) {
    Assert-SyntheticName $name
    & docker rm --force $name 2>$null | Out-Null
  }
  $tmpRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'tmp'))
  foreach ($path in @($oldRoot, $oldArchive)) {
    $full = [System.IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($tmpRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)) {
      throw 'Unsafe temporary cleanup target'
    }
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Recurse -Force }
  }
}
