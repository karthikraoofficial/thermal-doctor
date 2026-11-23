$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Optimize.psm1') -Force

function New-DemoState {
    [pscustomobject]@{
        Power      = [pscustomobject]@{ SchemeGuid = '11111111-2222-4333-8444-555555555555'; AcValue = 100; DcValue = 100 }
        Wsl        = [pscustomobject]@{ Path = 'C:\Users\demo\.wslconfig'; Exists = $false; Content = '' }
        RunValues  = @(
            [pscustomobject]@{ Label = 'Demo Container App'; Key = 'HKCU:\Software\Demo\Run'; Name = 'DemoContainer'; Found = $true; Value = 'C:\Program Files\Demo\container.exe'; ValueKind = 'String' }
        )
        Startup    = @(
            [pscustomobject]@{ Label = 'Demo Enabled'; Name = 'DemoEnabled'; ApprovedKey = 'HKLM:\Software\Demo\Approved'; Found = $true; Command = 'C:\Program Files\Demo\enabled.exe'; ApprovedHex = '020000000000000000000000'; Ask = $false }
            [pscustomobject]@{ Label = 'Demo Disabled'; Name = 'DemoDisabled'; ApprovedKey = 'HKLM:\Software\Demo\Approved'; Found = $true; Command = 'C:\Program Files\Demo\disabled.exe'; ApprovedHex = '03000000C050F4B92318DB01'; Ask = $false }
            [pscustomobject]@{ Label = 'Demo Missing'; Name = 'DemoMissing'; ApprovedKey = 'HKLM:\Software\Demo\Approved'; Found = $false; Command = ''; ApprovedHex = $null; Ask = $false }
            [pscustomobject]@{ Label = 'Demo Guarded'; Name = 'DemoGuarded'; ApprovedKey = 'HKLM:\Software\Demo\Approved'; Found = $true; Command = 'C:\Tools\guarded-item.exe'; ApprovedHex = '020000000000000000000000'; Ask = $false }
            [pscustomobject]@{ Label = 'Demo Ask'; Name = 'DemoAsk'; ApprovedKey = 'HKLM:\Software\Demo\Approved'; Found = $true; Command = 'C:\Program Files\Demo\ask.exe'; ApprovedHex = $null; Ask = $true }
        )
        TasksVerified = $true
        Tasks      = @(
            [pscustomobject]@{ Label = 'Demo Hidden Task'; TaskPath = '\Demo\'; TaskName = 'Hidden Task'; Found = $false; Enabled = $false; Command = '' }
            [pscustomobject]@{ Label = 'Demo Guarded Task'; TaskPath = '\Demo\'; TaskName = 'guarded-item'; Found = $false; Enabled = $false; Command = '' }
            [pscustomobject]@{ Label = 'Demo Task'; TaskPath = '\Demo\'; TaskName = 'Ready Task'; Found = $true; Enabled = $true; Command = 'C:\Program Files\Demo\task.exe' }
            [pscustomobject]@{ Label = 'Demo Off Task'; TaskPath = '\Demo\'; TaskName = 'Off Task'; Found = $true; Enabled = $false; Command = 'C:\Program Files\Demo\off.exe' }
            [pscustomobject]@{ Label = "Demo O'Brien Task"; TaskPath = '\Demo\'; TaskName = "O'Brien"; Found = $true; Enabled = $true; Command = 'C:\Program Files\Demo\quote.exe' }
        )
    }
}

$settings = [pscustomobject]@{ MaxProcessorPercent = 99; WslProcessors = 2; WslMemory = '4GB'; Protected = @('guarded-item') }
$now = [datetime]'2026-01-02T03:04:05'

Describe 'New-OptimizePlan' {
    $plan = @(New-OptimizePlan -State (New-DemoState) -Settings $settings -Now $now)
    function Get-Row($label) { $plan | Where-Object { $_.Label -eq $label } }

    It 'plans the processor cap with the original AC and DC values' {
        $row = Get-Row 'CPU turbo cap'
        $row.Status | Should Be 'Change'
        $row.Current | Should Be 'AC 100%, DC 100%'
        $row.New | Should Be 'AC 99%, DC 99%'
    }

    It 'reports unreadable power values as Unavailable' {
        $state = New-DemoState
        $state.Power.AcValue = $null
        $row = @(New-OptimizePlan -State $state -Settings $settings -Now $now) | Where-Object { $_.Label -eq 'CPU turbo cap' }
        $row.Status | Should Be 'Unavailable'
    }

    It 'marks enabled startup items as changes and disabled ones as no change' {
        (Get-Row 'Demo Enabled').Status | Should Be 'Change'
        (Get-Row 'Demo Disabled').Status | Should Be 'NoChange'
        (Get-Row 'Demo Missing').Status | Should Be 'NotFound'
    }

    It 'never makes a protected match applicable' {
        (Get-Row 'Demo Guarded').Status | Should Be 'Protected'
    }

    It 'marks an enabled item needing a separate decision as Ask' {
        (Get-Row 'Demo Ask').Status | Should Be 'Ask'
    }

    It 'shows no new state or undo for rows that will not change' {
        foreach ($label in 'Demo Disabled', 'Demo Missing', 'Demo Guarded', 'Demo Off Task') {
            (Get-Row $label).New | Should Be 'No change'
            (Get-Row $label).UndoText | Should Be 'Nothing to undo'
        }
    }

    Context 'when task state cannot be verified without elevation' {
        $state = New-DemoState
        $state.TasksVerified = $false
        $unverified = @(New-OptimizePlan -State $state -Settings $settings -Now $now)
        function Get-UnverifiedRow($label) { $unverified | Where-Object { $_.Label -eq $label } }

        It 'reports a task that reads as missing as Unavailable' {
            (Get-UnverifiedRow 'Demo Hidden Task').Status | Should Be 'Unavailable'
            (Get-UnverifiedRow 'Demo Hidden Task').Current | Should Be 'Unavailable without Administrator'
        }

        It 'reports a task that reads as disabled as Unavailable' {
            (Get-UnverifiedRow 'Demo Off Task').Status | Should Be 'Unavailable'
        }

        It 'still plans a task that reads as enabled' {
            (Get-UnverifiedRow 'Demo Task').Status | Should Be 'Change'
        }

        It 'keeps protected tasks Protected' {
            (Get-UnverifiedRow 'Demo Guarded Task').Status | Should Be 'Protected'
        }
    }

    It 'reports a missing task as NotFound when elevated' {
        (Get-Row 'Demo Hidden Task').Status | Should Be 'NotFound'
    }

    It 'plans only ready tasks for disabling' {
        (Get-Row 'Demo Task').Status | Should Be 'Change'
        (Get-Row 'Demo Off Task').Status | Should Be 'NoChange'
    }
}

Describe 'ConvertTo-WslConfig' {
    It 'creates a wsl2 section for a new file' {
        $text = ConvertTo-WslConfig -Existing '' -Processors 2 -Memory '4GB'
        $text | Should Be "[wsl2]`r`nprocessors=2`r`nmemory=4GB`r`n"
    }

    It 'updates the limits and keeps unrelated settings' {
        $existing = "[wsl2]`r`nmemory=8GB`r`nswap=0`r`n`r`n[experimental]`r`nsparseVhd=true`r`n"
        $text = ConvertTo-WslConfig -Existing $existing -Processors 2 -Memory '4GB'
        $text | Should Match 'memory=4GB'
        $text | Should Not Match 'memory=8GB'
        $text | Should Match 'swap=0'
        $text | Should Match '(?s)\[experimental\].*sparseVhd=true'
        ([regex]::Matches($text, 'processors=')).Count | Should Be 1
    }
}

Describe 'New-OptimizeUndoScript' {
    $plan = @(New-OptimizePlan -State (New-DemoState) -Settings $settings -Now $now)

    It 'restores recorded power values on the original scheme' {
        $text = New-OptimizeUndoScript -Actions @($plan | Where-Object { $_.Label -eq 'CPU turbo cap' })
        $text | Should Match 'setacvalueindex 11111111-2222-4333-8444-555555555555 SUB_PROCESSOR PROCTHROTTLEMAX 100'
        $text | Should Match 'setdcvalueindex 11111111-2222-4333-8444-555555555555 SUB_PROCESSOR PROCTHROTTLEMAX 100'
    }

    It 'restores the exact startup bytes' {
        $text = New-OptimizeUndoScript -Actions @($plan | Where-Object { $_.Label -eq 'Demo Enabled' })
        $text | Should Match '0x02,0x00,0x00,0x00'
    }

    It 'removes the approval value when none existed before' {
        $text = New-OptimizeUndoScript -Actions @($plan | Where-Object { $_.Label -eq 'Demo Ask' })
        $text | Should Match 'Remove-ItemProperty'
    }

    It 'escapes single quotes and produces a script that parses' {
        $text = New-OptimizeUndoScript -Actions @($plan | Where-Object { $_.Status -in 'Change', 'Ask' })
        $text | Should Match "O''Brien"
        $errors = $null
        [void][Management.Automation.PSParser]::Tokenize($text, [ref]$errors)
        @($errors).Count | Should Be 0
    }

    It 'undoes actions in reverse order' {
        $text = New-OptimizeUndoScript -Actions @($plan | Where-Object { $_.Label -in 'CPU turbo cap', 'Demo Task' })
        $text.IndexOf('Enable-ScheduledTask') | Should BeLessThan $text.IndexOf('setacvalueindex')
    }
}

Describe 'Get-DisabledStartupHex' {
    It 'writes the disabled marker followed by the FILETIME' {
        $hex = Get-DisabledStartupHex -Now ([datetime]::FromFileTimeUtc(0x01DB2318B9F450C0))
        $hex | Should Be '03000000C050F4B91823DB01'
    }
}
