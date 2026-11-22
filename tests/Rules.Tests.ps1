$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Rules.psm1') -Force

Describe 'Get-RedFlags' {
    $snapshot = Get-Content (Join-Path $PSScriptRoot 'fixtures\snapshot.json') -Raw | ConvertFrom-Json

    It 'ranks a known miner name as High and carries its SHA256' {
        $flag = @(Get-RedFlags -Snapshot $snapshot | Where-Object { $_.Pid -eq 4242 -and $_.Rule -eq 'KnownMiner' })

        $flag.Count | Should Be 1
        $flag[0].Severity | Should Be 'High'
        $flag[0].Sha256 | Should Be '0000000000000000000000000000000000000000000000000000000000000001'
    }

    It 'does not flag a signed process in its normal location' {
        @(Get-RedFlags -Snapshot $snapshot | Where-Object { $_.Pid -eq 1001 }).Count | Should Be 0
    }
}
