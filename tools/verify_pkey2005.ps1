# Test-only oracle: no licensing API calls or product-key installation.
$ErrorActionPreference = 'Stop'
$fixture = Get-Content -Raw (Join-Path $PSScriptRoot '../tests/fixtures/tsforge/key2005.json') | ConvertFrom-Json
foreach ($case in $fixture.random) {
    $random = [System.Random]::new([int]$case.seed)
    foreach ($expected in $case.values) {
        if ($random.Next(24) -ne [int]$expected) { throw "Random compatibility mismatch for seed $($case.seed)" }
    }
}
$alphabet = 'BCDFGHJKMPQRTVWXY2346789'
foreach ($case in $fixture.keys) {
    $seed = (([long]$case.group * 1000000000) + [long]$case.serial) % 4294967296
    if ($seed -gt 2147483647) { $seed -= 4294967296 }
    $random = [System.Random]::new([int]$seed)
    $raw = 'H4X3D' * 4
    for ($i = 0; $i -lt 5; $i++) { $raw += $alphabet[$random.Next(24)] }
    $parts = for ($i = 0; $i -lt 25; $i += 5) { $raw.Substring($i, 5) }
    if (($parts -join '-') -cne $case.text) { throw "PKEY2005 suffix mismatch for group $($case.group) serial $($case.serial)" }
}
Write-Host 'PKEY2005 fixtures match .NET Framework Random and upstream key formatting.'
