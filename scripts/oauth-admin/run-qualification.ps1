[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$runId = ([Guid]::NewGuid().ToString("N")).Substring(0, 12)
$containerName = "access-layer-oauth-admin-$runId"
$databaseName = "access_layer_oauth_admin_$runId"
$databaseUser = "oauth_admin_qualifier"
$passwordBytes = [byte[]]::new(24)
[Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
$databasePassword = -join ($passwordBytes | ForEach-Object { $_.ToString("x2") })
$started = $false

function Assert-SyntheticTarget {
  if ($containerName -notmatch '^access-layer-oauth-admin-[a-f0-9]{12}$' -or
      $databaseName -notmatch '^access_layer_oauth_admin_[a-f0-9]{12}$') {
    throw "Unsafe OAuth Admin qualification target"
  }
}

try {
  Assert-SyntheticTarget
  $dockerContext = (& docker context show).Trim()
  if ($LASTEXITCODE -ne 0 -or $dockerContext -ne "desktop-linux") {
    throw "OAuth Admin qualification requires the local Docker Desktop Linux context"
  }
  Push-Location $repoRoot
  try {
    $qualifiedCommit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $qualifiedCommit -notmatch '^[a-f0-9]{40}$') {
      throw "Unable to resolve the exact qualification commit"
    }
    $worktreeChanges = @(& git status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $worktreeChanges.Count -ne 0) {
      throw "OAuth Admin qualification requires a clean worktree"
    }
    & git merge-base --is-ancestor bae112404a8432b4d4ce7e3e70d96f2217ac7597 $qualifiedCommit
    if ($LASTEXITCODE -ne 0) { throw "Qualification commit must descend from the accepted baseline" }

    & docker run --detach --rm `
      --name $containerName `
      --label "access-layer.qualifier=oauth-admin-p0" `
      --publish "127.0.0.1::5432" `
      --env "POSTGRES_USER=$databaseUser" `
      --env "POSTGRES_PASSWORD=$databasePassword" `
      --env "POSTGRES_DB=$databaseName" `
      postgres:16 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to start disposable PostgreSQL 16" }
    $started = $true
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
      & docker exec $containerName pg_isready --quiet --username $databaseUser --dbname $databaseName
      if ($LASTEXITCODE -eq 0) { $ready = $true; break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "Disposable PostgreSQL did not become ready" }
    $binding = (& docker port $containerName 5432/tcp).Trim()
    if ($LASTEXITCODE -ne 0 -or $binding -notmatch '^127\.0\.0\.1:(\d+)$') {
      throw "Unsafe PostgreSQL port binding: expected loopback-only publication"
    }
    $databaseUrl = "postgresql://${databaseUser}:${databasePassword}@127.0.0.1:$($Matches[1])/${databaseName}"
    $env:DATABASE_URL = $databaseUrl
    & npm run migrate --silent
    if ($LASTEXITCODE -ne 0) { throw "Disposable PostgreSQL migrations failed" }
    $env:OAUTH_ADMIN_QUALIFY_DATABASE_URL = $databaseUrl
    & (Join-Path $repoRoot "node_modules\.bin\tsx.cmd") (Join-Path $PSScriptRoot "qualify.ts")
    if ($LASTEXITCODE -ne 0) { throw "OAuth Admin PostgreSQL qualification failed" }
    Write-Output "OAuth Admin PostgreSQL qualification commit: $qualifiedCommit"
  }
  finally { Pop-Location }
}
finally {
  Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
  Remove-Item Env:OAUTH_ADMIN_QUALIFY_DATABASE_URL -ErrorAction SilentlyContinue
  if ($started) {
    Assert-SyntheticTarget
    & docker rm --force $containerName 2>$null | Out-Null
  }
}
