$ErrorActionPreference = 'Stop'
$web = Join-Path $PSScriptRoot 'TicketSystem.Web'
$api = Join-Path $PSScriptRoot 'TicketSystem.Api'
$webOutput = Join-Path $web 'dist\ticket-system-web'
$staticOutput = Join-Path $api 'wwwroot'
$evidenceOutput = Join-Path $staticOutput 'Evidencias'

Push-Location $web
try {
    npm.cmd ci
    npm.cmd run build
} finally {
    Pop-Location
}

$browserOutput = Join-Path $webOutput 'browser'
if (Test-Path $browserOutput) { $webOutput = $browserOutput }
if (-not (Test-Path (Join-Path $webOutput 'index.html'))) {
    throw "No se encontró index.html en la salida Angular: $webOutput"
}
New-Item -ItemType Directory -Force -Path $staticOutput | Out-Null
Copy-Item -Path (Join-Path $webOutput '*') -Destination $staticOutput -Recurse -Force
New-Item -ItemType Directory -Force -Path $evidenceOutput | Out-Null
dotnet publish (Join-Path $api 'TicketSystem.Api.csproj') -c Release -o (Join-Path $PSScriptRoot 'publish')
Write-Host "Publicación lista en $PSScriptRoot\publish"
