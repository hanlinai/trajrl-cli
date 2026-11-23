# The installer "trajrl setup" runs on Windows (internal/sshsetup,
# embedded), for Windows' own OpenSSH. Windows PowerShell 5.1 and PowerShell 7 run it. The lines before
# it set $SbxConfig (this service's "Host *.DOMAIN" lines, their
# ProxyCommand the trajrl.exe that runs setup), $SbxDomain, $SbxLegacyPin
# (after an older setup, the known_hosts line it pinned the entry point's
# key with; '' otherwise) and $SbxRemove.
#
# It does what install-ssh.sh does: the lines go to the top of .ssh\config
# in a block marked for the domain, every file changed is backed up first,
# and a second run changes nothing. An older setup's block for the same
# domain ("# BEGIN sandbox SSH entry: NAME", with ProxyJump) is taken out,
# and with $SbxLegacyPin that pin too: trajrl proxy pins the entry point's
# key itself. With $SbxRemove it takes the block out again.
#
# What it writes is UTF-8 without a byte-order mark, its own lines ending in
# LF: OpenSSH reads neither UTF-16 nor a mark in the middle of a file. Lines
# of yours keep their own line ends.
#
# It is read from standard input, where a statement of several lines ends at
# the first empty line: so this is one block, with no empty line inside it
# and one after it.
& {
    $ErrorActionPreference = 'Stop'
    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $lf = [string][char]10
    function Stop-Setup([string]$Message) { throw "STOP: $Message" }
    #
    # Read-SshFile: a file's text, or $null if there is no such file. A
    # byte-order mark at its start is dropped: this script puts lines before it.
    function Read-SshFile([string]$Path) {
        if (-not [IO.File]::Exists($Path)) { return $null }
        $bytes = [IO.File]::ReadAllBytes($Path)
        $utf16 = ($bytes.Length -ge 2) -and ((($bytes[0] -eq 0xFF) -and ($bytes[1] -eq 0xFE)) -or (($bytes[0] -eq 0xFE) -and ($bytes[1] -eq 0xFF)))
        if ($utf16 -or ([Array]::IndexOf($bytes, [byte]0) -ge 0)) {
            Stop-Setup "$Path is UTF-16, which OpenSSH cannot read. Save it as UTF-8 and run this again; nothing was changed"
        }
        $skip = 0
        if (($bytes.Length -ge 3) -and ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) { $skip = 3 }
        try { $text = $utf8.GetString($bytes, $skip, $bytes.Length - $skip) } catch { $text = $null }
        if ($null -eq $text) { Stop-Setup "$Path is not UTF-8. Save it as UTF-8 and run this again; nothing was changed" }
        return $text
    }
    #
    # Save-SshFile: write a file that has to change, after a backup of what
    # is there. A file left with nothing in it is removed.
    function Save-SshFile([string]$Path, [string]$Text, [string]$Label) {
        if ([IO.File]::Exists($Path)) {
            $backup = $Path + '.' + $Label + '.' + [IO.Path]::GetRandomFileName().Replace('.', '').Substring(0, 8)
            [IO.File]::Copy($Path, $backup)
            Write-Output "Backup: $backup"
        }
        if ($Text.Length -eq 0) {
            [IO.File]::Delete($Path)
        } else {
            [IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
        }
    }
    #
    # Test-HostField: whether the first field of a known_hosts line names
    # $Name: a list of patterns, or |1|SALT|HASH with HASH the HMAC-SHA1 of
    # the name under SALT.
    function Test-HostField([string]$Field, [string]$Name) {
        if ($Field.StartsWith('|1|')) {
            $parts = $Field.Split('|')
            if ($parts.Length -ne 4) { return $false }
            try {
                $mac = New-Object System.Security.Cryptography.HMACSHA1 -ArgumentList (, [Convert]::FromBase64String($parts[2]))
                foreach ($n in @($Name, $Name.ToLowerInvariant())) {
                    $hash = [Convert]::ToBase64String($mac.ComputeHash([Text.Encoding]::ASCII.GetBytes($n)))
                    if ([string]::Equals($hash, $parts[3])) { return $true }
                }
            } catch { }
            return $false
        }
        $found = $false
        foreach ($pattern in $Field.Split(',')) {
            $negated = $pattern.StartsWith('!')
            if ($negated) { $pattern = $pattern.Substring(1) }
            $re = '^' + [regex]::Escape($pattern).Replace('\*', '.*').Replace('\?', '.') + '$'
            if ($Name -match $re) {
                if ($negated) { return $false }
                $found = $true
            }
        }
        return $found
    }
    #
    # Remove-Block: a config's text without the managed block, and without
    # an older setup's block whose lines are for *.DOMAIN ($Pattern); its
    # other lines stay as they are.
    function Remove-Block([string]$Text, [string]$Begin, [string]$End, [string]$Pattern, [string]$Path) {
        $kept = New-Object 'System.Collections.Generic.List[string]'
        $held = New-Object 'System.Collections.Generic.List[string]'
        $inside = $false
        $old = $false
        $mine = $false
        $oldEnd = ''
        foreach ($line in $Text.Split([char]10)) {
            $bare = $line.TrimEnd([char]13)
            if ($old) {
                $held.Add($line)
                if ([string]::Equals($bare, $Pattern) -or $bare.StartsWith($Pattern + ' ')) { $mine = $true }
                if ([string]::Equals($bare, $oldEnd)) {
                    $old = $false
                    if (-not $mine) { $kept.AddRange($held) }
                }
                continue
            }
            if ([string]::Equals($bare, $Begin)) { $inside = $true; continue }
            if ([string]::Equals($bare, $End)) { $inside = $false; continue }
            if ($inside) { continue }
            if ($bare.StartsWith('# BEGIN sandbox SSH entry: ')) {
                $old = $true
                $mine = $false
                $held.Clear()
                $held.Add($line)
                $oldEnd = '# END sandbox SSH entry: ' + $bare.Substring(27)
                continue
            }
            $kept.Add($line)
        }
        if ($inside -or $old) { Stop-Setup "the managed block in $Path is incomplete; nothing was changed" }
        return ($kept.ToArray() -join $lf)
    }
    #
    try {
        if ($SbxDomain -notmatch '^[a-z0-9][a-z0-9.-]*$') { Stop-Setup 'invalid domain' }
        #
        # The older setup's pin, if any: NAME KEYTYPE KEY.
        $pin = @()
        if ($SbxLegacyPin) {
            $pin = @($SbxLegacyPin.Trim().Split(' '))
            if ($pin.Length -ne 3) { Stop-Setup 'expected one pinned entry key' }
            if ($pin[0] -notmatch '^[\[\]a-zA-Z0-9._:-]+$') { Stop-Setup 'invalid entry name in the legacy pin' }
            try { $null = [Convert]::FromBase64String($pin[2]) } catch { Stop-Setup 'invalid entry host key in the legacy pin' }
        }
        #
        # The SSH directory: Windows' OpenSSH uses the profile directory.
        $userHome = $env:USERPROFILE
        if (-not $userHome) { $userHome = $HOME }
        $homeSsh = [IO.Path]::GetFullPath((Join-Path $userHome '.ssh'))
        $dir = $homeSsh
        if ($env:SBX_SSH_DIR) { $dir = [IO.Path]::GetFullPath($env:SBX_SSH_DIR) }
        $configPath = Join-Path $dir 'config'
        $hostsPath = Join-Path $dir 'known_hosts'
        $begin = "# BEGIN trajrl ssh: $SbxDomain"
        $end = "# END trajrl ssh: $SbxDomain"
        #
        # known_hosts without the older setup's pin, hashed ones too, each
        # with the empty line that setup put before it. Another key under
        # that name is not setup's and stays.
        $oldHosts = Read-SshFile $hostsPath
        $newHosts = $oldHosts
        if (($pin.Length -eq 3) -and ($null -ne $oldHosts)) {
            $hostLines = @($oldHosts.Split([char]10))
            $drop = @{}
            for ($i = 0; $i -lt $hostLines.Length; $i++) {
                $fields = @($hostLines[$i].Trim().Split([char[]]@(' ', [char]9), [StringSplitOptions]::RemoveEmptyEntries))
                if (($fields.Length -lt 3) -or $fields[0].StartsWith('#') -or $fields[0].StartsWith('@')) { continue }
                if ((Test-HostField $fields[0] $pin[0]) -and [string]::Equals($fields[1], $pin[1]) -and [string]::Equals($fields[2], $pin[2])) {
                    $drop[$i] = $true
                    if (($i -gt 0) -and ($hostLines[$i - 1].TrimEnd([char]13).Length -eq 0)) { $drop[$i - 1] = $true }
                }
            }
            $keptHosts = New-Object 'System.Collections.Generic.List[string]'
            for ($i = 0; $i -lt $hostLines.Length; $i++) { if (-not $drop.ContainsKey($i)) { $keptHosts.Add($hostLines[$i]) } }
            $newHosts = $keptHosts.ToArray() -join $lf
        }
        $oldConfig = Read-SshFile $configPath
        $rest = ''
        if ($null -ne $oldConfig) { $rest = Remove-Block $oldConfig $begin $end ('Host *.' + $SbxDomain) $configPath }
        #
        if ($SbxRemove) {
            $removed = $false
            if (($null -ne $oldConfig) -and -not [string]::Equals($rest, $oldConfig)) { Save-SshFile $configPath $rest 'before-remove'; $removed = $true }
            if (($null -ne $oldHosts) -and -not [string]::Equals($newHosts, $oldHosts)) { Save-SshFile $hostsPath $newHosts 'before-remove'; $removed = $true }
            if ($removed) { Write-Output "Removed trajrl's lines for *.$SbxDomain from $dir." } else { Write-Output "Nothing of trajrl's is installed in $dir." }
            return
        }
        #
        # In an SSH directory other than the profile's, the sandbox lines name
        # that directory's known-hosts files, so that a trial there reads
        # nothing of the real one.
        $lines = @($SbxConfig)
        if (-not [string]::Equals($dir.TrimEnd('\', '/'), $homeSsh.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
            $quoted = $dir.TrimEnd('\', '/').Replace('\', '/').Replace('%', '%%')
            if ($quoted.Contains('"')) { Stop-Setup "ssh_config cannot name ${dir}: choose a directory without a quote in its name" }
            for ($i = 0; $i -lt $lines.Length; $i++) {
                if ([string]::Equals($lines[$i], '    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/sbx_known_hosts')) {
                    $lines[$i] = '    UserKnownHostsFile "' + $quoted + '/known_hosts" "' + $quoted + '/sbx_known_hosts"'
                }
            }
        }
        # The block goes first: OpenSSH uses the first value it sees, so an
        # earlier Host * must not override these lines. It ends with Host *,
        # which gives the lines after it their scope back.
        $newConfig = $begin + $lf + ($lines -join $lf) + $lf + $lf + 'Host *' + $lf + $end + $lf + $rest
        $null = [IO.Directory]::CreateDirectory($dir)
        #
        # Let ssh itself read the combined config before it replaces yours.
        $ssh = @(Get-Command ssh -CommandType Application -ErrorAction SilentlyContinue)
        if ($ssh.Length -gt 0) {
            $trial = Join-Path $dir ('.trajrl-ssh.' + [IO.Path]::GetRandomFileName().Replace('.', ''))
            try {
                [IO.File]::WriteAllText($trial, $newConfig, (New-Object System.Text.UTF8Encoding($false)))
                $start = New-Object System.Diagnostics.ProcessStartInfo
                $start.FileName = $ssh[0].Path
                $start.Arguments = '-G -F "' + $trial + '" trajrl-check.' + $SbxDomain
                $start.UseShellExecute = $false
                $start.CreateNoWindow = $true
                $start.RedirectStandardInput = $true
                $start.RedirectStandardOutput = $true
                $start.RedirectStandardError = $true
                $process = [Diagnostics.Process]::Start($start)
                $process.StandardInput.Close()
                $complaint = $process.StandardError.ReadToEndAsync()
                $null = $process.StandardOutput.ReadToEnd()
                $process.WaitForExit()
                $valid = $process.ExitCode -eq 0
                $why = $complaint.Result.Trim()
            } finally {
                [IO.File]::Delete($trial)
            }
            if (-not $valid) { Stop-Setup "the combined SSH config is invalid; nothing was changed: $why" }
        }
        if (-not [string]::Equals($newConfig, $oldConfig)) { Save-SshFile $configPath $newConfig 'before-entry' }
        if (($null -ne $oldHosts) -and -not [string]::Equals($newHosts, $oldHosts)) { Save-SshFile $hostsPath $newHosts 'before-entry' }
        Write-Output "Installed trajrl's lines for *.$SbxDomain in $dir."
        Write-Output "Log in to a sandbox of yours: ssh root@NAME.$SbxDomain"
    } catch {
        $message = $_.Exception.Message
        if (-not $message.StartsWith('STOP: ')) { $message = 'STOP: ' + $message }
        [Console]::Error.WriteLine($message)
        exit 1
    }
}
