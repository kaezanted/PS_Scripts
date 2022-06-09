# https://jamesdatatechq.wordpress.com/2015/01/04/caesar-shift-cipher-using-powershell/
#https://netsec.expert/posts/write-a-crypter-in-any-language/

# Caesar cipher ?
# Remplacement d'une lettre par une autre > répété de multiple fois avec variations de la clé pour brouiller les pistes
# - Possibilité d'ajouter des randoms pas trop élevé pour ajouter du brute force obligatoire sur certaine phase ?

while ($a = "1") { nslookup -querytype=txt sarouman.mechant 127.0.0.1 ; nslookup -querytype=txt Gandoulf.com 127.0.0.1 ; nslookup -querytype=txt Jean.neige 127.0.0.1 ; nslookup -querytype=txt Babidi.boo 127.0.0.1 ; nslookup -querytype=txt Isildur.key 127.0.0.1 ; nslookup -querytype=txt herbe-a-pipe.com 127.0.0.1 ; nslookup -querytype=txt doliprane.com 127.0.0.1 ;}


$Key = Read-host "Parlez, ami, et entrez :"
[string]$date = get-date
$txt = get-content lotr.txt

# [int][char]'a' Pour un traitement par char
#$clearflag = [int[]]"$txt".ToCharArray() # Pour un texte complet
#Attention aux accents a virer du txt avant. 

#Encrypt caesar cipher
$String = [char[]]"$txt"
foreach ($letter in $string) {
    $nbr = [int[]][char]$letter

    [string]$string_nbr = $nbr #ASCII code to string 
    [int]$int_nbr = $string_nbr #ASCII code in string to INT
    [int]$Enc_nbr = $int_nbr + 2 #Rotation ASCII >>> chiffrement
    [int]$Enc_nbr2 = $Enc_nbr - $Key.length
    #Recuperation de la date et convertion du char en ASCII code puis ajout et soustraction à la valeur deja encrypt precedemment
    [int]$Enc_nbr3 = ($Enc_nbr2 + [convert]::Toint32($date[1]) - [convert]::Toint32($date[3])) 
    #[int]$enc_nbr4 = (($str = [char[]]$key) | % {$p = [int[]][char]$z ; [int]$v = $v + $p } ) 
    $str = [char[]]$key
    #foreach ($z in $str){$p = [int[]][char]$z;$v = $v + $p;$o = ($v | measure -sum).sum}
    
    $ASCII_table = $ASCII_table + " " + $Enc_nbr3
    [string]$enc_letter = [char]$Enc_nbr3 #Récup du caractere a partir du code ASCII
    $encryptedtxt = $encryptedtxt + $enc_letter # Ajout du caractere au message encrypte
}

#2e encrypt RC4
# $encryptedtxt est en ASCII le but est maintenant de récupérer le txt encrypt, le traduire en binaire par octet et d effectuer une rotation sur certains bits 

$bin = ([system.Text.Encoding]::Default.GetBytes($encryptedtxt) | %{[System.Convert]::ToString($_,2).PadLeft(8,'0') })
foreach ($oct in $bin)
{
    #Récupération de chaque Octet et rotation de 3 bits vers la gauche  
    [string]$g = $oct[0..7]
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

#2e encrypt DES into B64
$filedata = [System.IO.File]::ReadAllBytes("titi.txt")
#[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
$DES = New-Object "System.Security.Cryptography.DESCryptoServiceProvider"
$encryptor = $des.CreateEncryptor()
$encryptedData = $encryptor.transformFinalBlock($filedata, 0, $filedata.length)
[byte[]] $fullData = $DES.IV + $encryptedData
$DES.dispose()
$b64encrypted = [System.Convert]::ToBase64String($fullData)
$fullData > encrypted_DES.txt
$b64encrypted > encrypted_DES_B64.txt



#Decrypt
$ebin = get-content flag.txt
#Decrypt rota binaire
foreach ($octe in $ebin.split(" "))
{
    #Récupération de chaque Octet et rotation de 3 bits vers la gauche  
    [string]$k = $octe[0..7]
    $h = ([string]$k).split(" ")
    switch ($h[1]) {
        0 {
            $h[1] = 1
        }
        1 {
            $h[1] = 0
        }
    }
        switch ($h[3]) {
        0 {
            $h[3] = 1
        }
        1 {
            $h[3] = 0
        }
    }
        switch ($h[6]) {
        1 {
            $h[6] = 0
        }
        0 {
            $h[6] = 1
        }
    }
    $y = $h -join ""
    $decbin = $decbin + " " + $y
}

$estr = [char[]]$encryptedtxt
foreach ($enc_letter in $estr) {
    $dbr = [int[]][char]$enc_letter
    [string]$string_dbr = $dbr #ASCII code to string 
    [int]$int_dbr = $string_dbr #ASCII code in string to INT

    #if (($int_dbr -ge 34) -and ($int_dbr -le 126)) {
    #    [int]$int_dbr2 = $int_dbr - 1
    #}
    
    [int]$int_dbr3 = ($int_dbr + 50 - 54)
    [int]$int_dbr4 = $int_dbr3 + $key.length #9
    [int]$dec_ascii = $int_dbr4 - 2 #Rotation ASCII >>> chiffrement
    [string]$dec_letter = [char]$dec_ascii

    $decryptedtxt = $decryptedtxt + $dec_letter
}


#Decrypt version ASCII
$estr = $decbin.split(" ")
foreach ($enc_letter in $estr) {
    #$dbr = [int[]][char]$enc_letter
    [string]$string_dbr = $enc_letter #ASCII code to string 
    [int]$int_dbr = $string_dbr #ASCII code in string to INT

    #if (($int_dbr -ge 34) -and ($int_dbr -le 126)) {
    #    [int]$int_dbr2 = $int_dbr - 1
    #}
    
    [int]$int_dbr3 = ($int_dbr + 50 - 54)
    [int]$int_dbr4 = $int_dbr3 + $key.length
    [int]$dec_ascii = $int_dbr4 - 2 #Rotation ASCII >>> dechiffrement
    [string]$dec_letter = [char]$dec_ascii

    $decryptedtxt = $decryptedtxt + $dec_letter
}
