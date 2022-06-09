
$encfile = "Qm9uam91ciwgamUgbSdhcHBlbGxlIGdhbmRvdWxmIGV0IGplIHZpZW5zIGR1IHNlaWduZXVyIGRlcyBhbm5lYXV4LgpNYWludGVuYXQgbidvdWJsaWV6IHBhcyBkZSBjaGVyY2jpIFNhdHJvdW1hbiAh"
#Texte encodé en B64 
#Bonjour, je m'appelle gandoulf et je viens du seigneur des anneaux.
#Maintenant n'oubliez pas de cherché Satrouman !
$enckey = "TGVnb2xhcw==" #cle encodee en B64 = Legolas

#decrypt
$aes = New-Object "System.Security.Cryptography.AesManaged"
$aes.Mode = [System.Security.Cryptography.CipherMode]::EBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
$aes.BlockSize = 64
$aes.KeySize = 64
$aes.Key = [System.Convert]::FromBase64String($encKey)
$bytes = [System.Convert]::FromBase64String($encData)
$IV = $bytes[0..15]
$aes.IV = $IV
$decryptor = $aes.CreateDecryptor();
$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
$aes.Dispose()

$code = [System.Text.Encoding]::UTF8.GetString($byteOutArray) 
echo $code
#Invoke-Expression($code)

$filename = "c:\users\kaezan\desktop\lotr.txt"

# Read file
$fileData = [System.IO.File]::ReadAllBytes($filename)

# generate key
$aes = New-Object "System.Security.Cryptography.AesManaged"
$aes.Mode = [System.Security.Cryptography.CipherMode]::ECB # Don't ever use ECB for anything other than messing around
$aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros #this is also a terrible idea
$aes.BlockSize = 128
$aes.KeySize = 128
$aes.GenerateKey()
$b64key = [System.Convert]::ToBase64String($aes.Key)

# encrypt
$encryptor = $aes.CreateEncryptor()
$encryptedData = $encryptor.TransformFinalBlock($fileData, 0, $fileData.Length);
[byte[]] $fullData = $aes.IV + $encryptedData
$aes.Dispose()
$b64encrypted = [System.Convert]::ToBase64String($fullData)