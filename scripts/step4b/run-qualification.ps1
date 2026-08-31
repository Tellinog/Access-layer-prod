[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runId = ([Guid]::NewGuid().ToString("N")).Substring(0, 12)
$sourceName = "access-layer-step4b-source-$runId"
$restoreName = "access-layer-step4b-restore-$runId"
$sourceDatabase = "access_layer_step4b_source_$runId"
$restoreDatabase = "access_layer_step4b_restore_$runId"
$databaseUser = "step4b_qualifier"
$passwordBytes = [byte[]]::new(24)
$passwordGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
$passwordGenerator.GetBytes($passwordBytes)
$passwordGenerator.Dispose()
$databasePassword = -join ($passwordBytes | ForEach-Object { $_.ToString("x2") })
$started = [System.Collections.Generic.List[string]]::new()

function Assert-SyntheticTarget([string]$ContainerName, [string]$DatabaseName) {
  if ($ContainerName -notmatch '^access-layer-step4b-(source|restore)-[a-f0-9]{12}$') {
    throw "Unsafe Step4B container name"
  }
  if ($DatabaseName -notmatch '^access_layer_step4b_(source|restore)_[a-f0-9]{12}$') {
    throw "Unsafe Step4B database name"
  }
  if ($DatabaseName -match '(prod|production|live)') {
    throw "Production-like database names are forbidden"
  }
}

function Start-Step4BPostgres([string]$ContainerName, [string]$DatabaseName) {
  Assert-SyntheticTarget $ContainerName $DatabaseName
  $containerId = & docker run --detach --rm `
    --name $ContainerName `
    --label "access-layer.qualifier=step4b" `
    --publish "127.0.0.1::5432" `
    --env "POSTGRES_USER=$databaseUser" `
    --env "POSTGRES_PASSWORD=$databasePassword" `
    --env "POSTGRES_DB=$DatabaseName" `
    postgres:16
  if ($LASTEXITCODE -ne 0 -or -not $containerId) {
    throw "Failed to start disposable PostgreSQL 16 container"
  }
  $started.Add($ContainerName)

  $ready = $false
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    & docker exec $ContainerName pg_isready --quiet --username $databaseUser --dbname $DatabaseName
    if ($LASTEXITCODE -eq 0) {
      $ready = $true
      break
    }
    Start-Sleep -Milliseconds 500
  }
  if (-not $ready) {
    throw "Disposable PostgreSQL 16 container did not become ready"
  }

  $binding = (& docker port $ContainerName 5432/tcp).Trim()
  if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') {
    throw "Unsafe PostgreSQL port binding: expected loopback-only publication"
  }
  return [int]$Matches[1]
}

try {
  if ($sourceName -eq $restoreName -or $sourceDatabase -eq $restoreDatabase) {
    throw "Source and restore targets must be distinct"
  }
  $dockerContext = (& docker context show).Trim()
  if ($dockerContext -ne "desktop-linux") {
    throw "Step4B requires the local Docker Desktop Linux context"
  }

  $sourcePort = Start-Step4BPostgres $sourceName $sourceDatabase
  $restorePort = Start-Step4BPostgres $restoreName $restoreDatabase
  if ($sourcePort -eq $restorePort) {
    throw "Source and restore targets unexpectedly share a port"
  }

  $sourceUrl = "postgresql://${databaseUser}:${databasePassword}@127.0.0.1:${sourcePort}/${sourceDatabase}"
  $restoreUrl = "postgresql://${databaseUser}:${databasePassword}@127.0.0.1:${restorePort}/${restoreDatabase}"

  Push-Location $repoRoot
  try {
    $qualifiedCommit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $qualifiedCommit -notmatch '^[a-f0-9]{40}$') {
      throw "Unable to resolve the exact qualification commit"
    }
    $worktreeChanges = @(& git status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw "Unable to verify qualification worktree state" }
    if ($worktreeChanges.Count -ne 0) {
      throw "Step4B qualification requires a clean worktree so runtime evidence is attributable to the exact commit"
    }
    & git merge-base --is-ancestor 1757a40c6369be59427da6618fa8126605a51550 $qualifiedCommit
    if ($LASTEXITCODE -ne 0) { throw "Qualification commit must descend from approved Step 4A baseline" }

    $env:DATABASE_URL = $sourceUrl
    & npm run migrate --silent
    if ($LASTEXITCODE -ne 0) { throw "Source migrations failed" }

    $env:DATABASE_URL = $restoreUrl
    & npm run migrate --silent
    if ($LASTEXITCODE -ne 0) { throw "Restore migrations failed" }

    $env:STEP4B_SOURCE_DATABASE_URL = $sourceUrl
    $env:STEP4B_RESTORE_DATABASE_URL = $restoreUrl
    $env:STEP4B_EXPECTED_COMMIT = $qualifiedCommit
    & (Join-Path $repoRoot "node_modules\.bin\tsx.cmd") (Join-Path $repoRoot "scripts\step4b\qualify.ts")
    if ($LASTEXITCODE -ne 0) { throw "Step4B qualification harness failed" }
  }
  finally {
    Pop-Location
  }
}
finally {
  Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
  Remove-Item Env:STEP4B_SOURCE_DATABASE_URL -ErrorAction SilentlyContinue
  Remove-Item Env:STEP4B_RESTORE_DATABASE_URL -ErrorAction SilentlyContinue
  Remove-Item Env:STEP4B_EXPECTED_COMMIT -ErrorAction SilentlyContinue
  foreach ($containerName in $started) {
    Assert-SyntheticTarget $containerName ($(if ($containerName -eq $sourceName) { $sourceDatabase } else { $restoreDatabase }))
    & docker rm --force $containerName 2>$null | Out-Null
  }
}
