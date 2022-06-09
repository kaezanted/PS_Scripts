$Key = Read-host "Demandez le domaine cle et une reponse vous sera peut etre donnee dans le texte"
[string]$date = get-date
$Flag = get-content flag.txt
$IPAddress = "127.0.0.1"
$ICMPClient = New-Object System.Net.NetworkInformation.Ping
$PingOptions = New-Object System.Net.NetworkInformation.PingOptions
$PingOptions.DontFragment = $true

$Str = [char[]]"$flag"
foreach ($ltr in $Str) {
    $ibr = [int[]][char]$ltr
    [string]$sibr = $ibr 
    [int]$iibr = $sibr 
    [int]$Eebr = $iibr + 2 
    [int]$Eeebr = $Eebr - $Key.length
    [int]$Eeeebr = ($Eeebr + [convert]::Toint32($date[1]) - [convert]::Toint32($date[3])) 
    $sstr = [char[]]$key
    foreach ($z in $sstr){
        $p = [int[]][char]$z
        $v = $v + $p
        [string]$Eeeeebr = ($v | measure -sum).sum}
    $encrypted = $encrypted + " " + $Eeeebr
    }

$b = ([system.Text.Encoding]::Default.GetBytes($encrypted) | %{[System.Convert]::ToString($_,2).PadLeft(8,'0') })
foreach ($o in $b)
{
    [string]$g = $o[0..7]
    $t = ([string]$g).split(" ")
    switch ($t[1]) {
        0 {
            $t[1] = 1
        }
        1 {
            $t[1] = 0
        }
    }
        switch ($t[3]) {
        0 {
            $t[3] = 1
        }
        1 {
            $t[3] = 0
        }
    }
        switch ($t[6]) {
        1 {
            $t[6] = 0
        }
        0 {
            $t[6] = 1
        }
    }
    $u = $t -join ""
    $ebin = $ebin + " " + $u
}
$ebin > flag.txt

[int]$bufSize = 1472
$inFile = "flag.txt"
$stream = [System.IO.File]::OpenRead($inFile)
$chunkNum = 0
$TotalChunks = [math]::floor($stream.Length / 1472)
$barr = New-Object byte[] $bufSize
    
$sendbytes = ([text.encoding]::ASCII).GetBytes("You shall not pass")
$ICMPClient.Send($IPAddress,10, $sendbytes, $PingOptions) | Out-Null

    while ($bytesRead = $stream.Read($barr, 0, $bufsize)) {
        $ICMPClient.Send($IPAddress,10, $barr, $PingOptions) | Out-Null
        $ICMPClient.PingCompleted

        sleep 1
        Write-Output "Done with $chunkNum out of $TotalChunks"
        $chunkNum += 1
    }
$sendbytes = ([text.encoding]::ASCII).GetBytes("Well, well, apparently you passed...")
$ICMPClient.Send($IPAddress,10, $sendbytes, $PingOptions) | Out-Null