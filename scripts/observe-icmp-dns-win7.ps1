# Windows 7 SP1 / PowerShell 2.0: inspect ICMP errors associated with
# three specific public DNS IPs. Run elevated on an authorized PC only.
# This uses Windows' built-in raw IPv4 socket (SIO_RCVALL).
# It prints only ICMP events quoting the listed UDP requests;
# unrelated packets are discarded in memory and no capture file is written.
# Usage: powershell -NoProfile -File .\scripts\observe-icmp-dns-win7.ps1 -LocalIPv4 192.168.245.38
param(
    [Parameter(Mandatory=$true)][string]$LocalIPv4,
    [int]$CaptureSeconds = 8
)
$ErrorActionPreference = 'Stop'
if ($CaptureSeconds -lt 3 -or $CaptureSeconds -gt 20) {
    throw 'CaptureSeconds must be within 3..20.'
}
$targets = @('1.1.1.1', '1.1.1.2', '1.0.0.1')
$null = [System.Net.IPAddress]::Parse($LocalIPv4)
$socket = $null
$job = $null
$matches = 0
try {
    $socket = New-Object Net.Sockets.Socket(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Raw,
        [Net.Sockets.ProtocolType]::IP
    )
    $socket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIPv4), 0)))
    $socket.IOControl(
        [Net.Sockets.IOControlCode]::ReceiveAll,
        [byte[]](1,0,0,0),
        (New-Object 'byte[]' 4)
    ) | Out-Null
    $socket.ReceiveTimeout = 300

    # Run the fixed, low-volume test in another PowerShell job while receiving.
    $job = Start-Job -ScriptBlock {
        Start-Sleep -Milliseconds 500
        $query = [byte[]](
          0x73,0x5A,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
          0x07,0x65,0x78,0x61,0x6D,0x70,0x6C,0x65,
          0x03,0x63,0x6F,0x6D,0x00,0x00,0x01,0x00,0x01
        )
        foreach ($target in @('1.1.1.1','1.1.1.2','1.0.0.1')) {
            $u = New-Object Net.Sockets.UdpClient
            $u.Client.ReceiveTimeout = 650
            try {
                $u.Connect($target, 53)
                $u.Send($query, $query.Length) | Out-Null
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $answer = $u.Receive([ref]$ep)
                Write-Output ('DNS_RESULT target=' + $target + ' response_bytes=' + $answer.Length)
            } catch {
                Write-Output ('DNS_RESULT target=' + $target + ' error=' + $_.Exception.Message)
            } finally {
                $u.Close()
            }
            Start-Sleep -Milliseconds 200
        }
    }
    $until = (Get-Date).AddSeconds($CaptureSeconds)
    $packet = New-Object 'byte[]' 16384
    while ((Get-Date) -lt $until) {
        try {
            $n = $socket.Receive($packet)
        } catch [Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq 'TimedOut') { continue }
            throw
        }
        if ($n -lt 56) { continue }
        $ihl = ([int]$packet[0] -band 15) * 4
        if ($ihl -lt 20 -or $n -lt ($ihl + 8 + 20)) { continue }
        if ($packet[9] -ne 1 -or $packet[$ihl] -ne 3) { continue }
        $inner = $ihl + 8
        $innerIhl = ([int]$packet[$inner] -band 15) * 4
        if ($innerIhl -lt 20 -or $n -lt ($inner + $innerIhl + 8)) { continue }
        if ($packet[$inner + 9] -ne 17) { continue }
        $dst = (@(
            $packet[$inner+16],$packet[$inner+17],
            $packet[$inner+18],$packet[$inner+19]
        ) -join '.')
        if ($targets -notcontains $dst) { continue }
        $port = [int]$packet[$inner+$innerIhl+2]*256 +
                [int]$packet[$inner+$innerIhl+3]
        if ($port -ne 53) { continue }
        $src = (@($packet[12],$packet[13],$packet[14],$packet[15]) -join '.')
        Write-Output ('ICMP_ERROR src=' + $src +
            ' quoted_dst=' + $dst + ':53' +
            ' icmp_type=' + $packet[$ihl] +
            ' icmp_code=' + $packet[$ihl+1] +
            ' reply_ttl=' + $packet[8] +
            ' ip_packet_bytes=' + $n)
        $matches++
    }
} finally {
    if ($socket -ne $null) { $socket.Close() }
    if ($job -ne $null) {
        Wait-Job $job -Timeout 3 | Out-Null
        Receive-Job $job
        Remove-Job $job -Force
    }
    Write-Output ('RELATED_ICMP_EVENTS=' + $matches)
}
