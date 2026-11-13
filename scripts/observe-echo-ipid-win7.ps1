# Windows 7 SP1 / PowerShell 2.0; run elevated on an owned or authorized host.
# Observe IPv4 IP-ID/TTL of ICMP Echo Replies only from known targets.
# No capture file is written, and no unrelated packet details are printed.
# This is a correlation probe, NOT a physical-device identity proof.
# Example (process-scoped policy only):
# powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\observe-echo-ipid-win7.ps1 -LocalIPv4 192.168.245.38
param(
    [Parameter(Mandatory=$true)][string]$LocalIPv4,
    [int]$CaptureSeconds = 6
)
$ErrorActionPreference = 'Stop'
if ($CaptureSeconds -lt 4 -or $CaptureSeconds -gt 15) {
    throw 'CaptureSeconds must be between 4 and 15.'
}
$null = [Net.IPAddress]::Parse($LocalIPv4)
$targets = @('1.1.1.2','10.0.2.10','1.1.1.1')
$socket = $null
$job = $null
$count = 0
try {
    $socket = New-Object Net.Sockets.Socket(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Raw,
        [Net.Sockets.ProtocolType]::IP
    )
    $socket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIPv4),0)))
    $socket.IOControl(
        [Net.Sockets.IOControlCode]::ReceiveAll,
        [byte[]](1,0,0,0),
        (New-Object 'byte[]' 4)
    ) | Out-Null
    $socket.ReceiveTimeout = 250
    $job = Start-Job -ScriptBlock {
        Start-Sleep -Milliseconds 350
        foreach ($target in @(
            '1.1.1.2','10.0.2.10',
            '1.1.1.2','10.0.2.10',
            '1.1.1.1','1.1.1.1'
        )) {
            ping.exe -n 1 -w 400 $target | Out-Null
        }
    }
    Write-Output ('UTC_START=' + [DateTime]::UtcNow.ToString('o'))
    $packet = New-Object 'byte[]' 8192
    $until = (Get-Date).AddSeconds($CaptureSeconds)
    while ((Get-Date) -lt $until) {
        try {
            $n = $socket.Receive($packet)
        } catch [Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq 'TimedOut') { continue }
            throw
        }
        if ($n -lt 28 -or $packet[9] -ne 1) { continue }
        $ihl = ([int]$packet[0] -band 15) * 4
        if ($ihl -lt 20 -or $n -lt ($ihl + 8)) { continue }
        if ($packet[$ihl] -ne 0) { continue }
        $src = (@(
            $packet[12],$packet[13],$packet[14],$packet[15]
        ) -join '.')
        if ($targets -notcontains $src) { continue }
        $ipId = [int]$packet[4]*256 + [int]$packet[5]
        $flagsFrag = [int]$packet[6]*256 + [int]$packet[7]
        $ipLength = [int]$packet[2]*256 + [int]$packet[3]
        Write-Output ('ICMP_ECHO src=' + $src +
            ' ttl=' + $packet[8] +
            ' ip_id=' + $ipId +
            ' flags_frag=' + $flagsFrag +
            ' iplen=' + $ipLength)
        $count++
    }
} finally {
    if ($socket -ne $null) { $socket.Close() }
    if ($job -ne $null) {
        Wait-Job $job -Timeout 2 | Out-Null
        Remove-Job $job -Force
    }
    Write-Output ('MATCHED_ECHO_REPLIES=' + $count)
}
