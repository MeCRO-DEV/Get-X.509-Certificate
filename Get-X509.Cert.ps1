#########################################################
# Retrieve SSL certificate from the server and save it
# in PEM format
# Author: David Wang  
# usage: Get-X509.Cert.ps1 SERVER_NAME [PORT_NUMBER]
#########################################################
# The MIT License (MIT)
#
# Copyright (c) 2022, David Wang
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
# associated documentation files (the "Software"), to deal in the Software without restriction, 
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.#>
###############################################################################################################
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [int]$Port = 443
)

# Dummy callback function, does nothing
$Callback = { 
    param(
        $sender, # System variable, out
        $cert, 
        $chain, 
        $errors
    ) 
    
    return $true 
}

Write-Host -Foreground Yellow "=== 1. Server Name Lookup ==="
try {
    $test = Resolve-DnsName $ServerName 2>$null 3>$null
    } catch {
}

if(!$test -eq $null){
    Write-Host -Foreground Red "Wrong server name: $ServerName"
    exit
} Else {
    $test | Format-List -Property *
}

Write-Host -Foreground Yellow "=== 2. Server Connection Test ==="
try {
    $test = Test-NetConnection -ComputerName $ServerName -Port $Port 2>$null 3>$null
} catch {
}

if(!$test.TcpTestSucceeded){
    Write-Host -Foreground Red "Server connection test failed"
    exit
} else {
    $test | Format-List -Property *
}

Write-Host -Foreground Yellow "=== 3. SSL/TLS Handshake Test ==="
$Cert = $null
$TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

$TcpClient.Connect($ServerName, $Port)
$TcpStream = $TcpClient.GetStream()

$SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)

$SslStream.AuthenticateAsClient('')
$Cert = $SslStream.RemoteCertificate
$SslStream.Dispose()
$TcpClient.Dispose()

if ($Cert) {
    if ($Cert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Cert
    }
    $Cert | Format-List -Property *
} else {
    Write-Host -ForegroundColor Yellow "Invalid certificate received from SSL handshake."
}

# Save the extacted certificate to a file
Write-Host -Foreground Yellow "=== 4. Generating PEM file (Base64 Encoding) ==="
$Base64PEM = new-object System.Text.StringBuilder
$Base64PEM.AppendLine("-----BEGIN CERTIFICATE-----")
$Base64PEM.AppendLine([System.Convert]::ToBase64String($Cert.RawData, 1))
$Base64PEM.AppendLine("-----END CERTIFICATE-----")
$Base64PEM.ToString() | out-file "$ServerName.pem"

Write-Host -Foreground Magenta "$ServerName.pem is ready."