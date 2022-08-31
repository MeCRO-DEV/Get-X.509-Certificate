####################################################################################
# Retrieve SSL certificate from the server and save it
# in PEM format
# usage: Get-X509.Cert.ps1 SERVER_NAME [PORT_NUMBER] [-SMTP] [-tv PROTOCOL_VERSION]
# -tv : TLS version, possible value: SSLv2,SSLv3,TLSv10,TLSv11,TLSv12,TLSv13
####################################################################################
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
#requires -version 5
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$ServerName,
    [int]$Port = 443,
    [switch]$smtp,
    [String]$tv # TLS version, possible value: SSLv2,SSLv3,TLSv10,TLSv11,TLSv12,TLSv13
)

[String]$Protocol = ""
[string]$Filename = ""

Switch ($tv) {
    "SSLv2"   { $Protocol = [System.Security.Authentication.SslProtocols]::ssl2  }
    "SSLv3"   { $Protocol = [System.Security.Authentication.SslProtocols]::ssl3  }
    "TLSv10"  { $Protocol = [System.Security.Authentication.SslProtocols]::tls   }
    "TLSv11"  { $Protocol = [System.Security.Authentication.SslProtocols]::tls11 }
    "TLSv12"  { $Protocol = [System.Security.Authentication.SslProtocols]::tls12 }
    "TLSv13"  { $Protocol = [System.Security.Authentication.SslProtocols]::tls13 }
    default   { 
        Write-Host -ForegroundColor Cyan "===========> Invalid SSL/TLS version $tv, defaulting to TLSv12."
        $Protocol = [System.Security.Authentication.SslProtocols]::Tls12
        $tv = "TLSv12" # Default protocol version is TLSv12
        Start-Sleep -Seconds 5
    }
}

$Filename = $ServerName + "-$tv"

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

if($smtp.IsPresent){
    Write-Host -Foreground Yellow "=== 3. TCP Handshake and SMPT Connection Test ==="
    Write-Host "                "
    Write-Host("Connecting to $ServerName $Port") -ForegroundColor Green
    $socket = new-object System.Net.Sockets.TcpClient($ServerName, $Port)
    $stream = $socket.GetStream()
    $streamWriter = new-object System.IO.StreamWriter($stream)
    $streamReader = new-object System.IO.StreamReader($stream)
    $stream.ReadTimeout = 5000
    $stream.WriteTimeout = 5000  
    $streamWriter.AutoFlush = $true
    $sslStream = New-Object System.Net.Security.SslStream($stream)
    $sslStream.ReadTimeout = 5000
    $sslStream.WriteTimeout = 5000       
    $ConnectResponse = $streamReader.ReadLine();
    Write-Host($ConnectResponse)
    if(!$ConnectResponse.StartsWith("220")){
        throw "Error connecting to the SMTP Server"
    }

    #Send "EHLO"
    $Sendingdomain = "gmail.com"
    Write-Host(("EHLO " + $Sendingdomain)) -ForegroundColor Green
    $streamWriter.WriteLine(("EHLO " + $Sendingdomain));

    $response = @()

    Try {
        while($streamReader.EndOfStream -ne $true) {
            $ehloResponse = $streamReader.ReadLine();
            Write-Host($ehloResponse)
            $response += $ehloResponse
        }
    } catch {

        If ($response -match "STARTTLS")
        {
            Write-Host("STARTTLS") -ForegroundColor Green
            $streamWriter.WriteLine("STARTTLS");
            $startTLSResponse = $streamReader.ReadLine();
            Write-Host($startTLSResponse)

            Write-Host "                "
            Write-Host -Foreground Yellow "=== 4. Retrieving Certificate from Remote Server ==="
            $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
            try {
                $sslStream.AuthenticateAsClient($ServerName,$CertCollection,$Protocol,$false)
            } catch {
                Write-Host -ForegroundColor Red "The client and server cannot communicate, because they do not possess a common algorithm"
                exit
            }
            
            $Certificate = $sslStream.RemoteCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $Cert = $sslStream.RemoteCertificate

            $sslStream.RemoteCertificate | Format-List -Property *

            Write-Host -Foreground Yellow "=== 5. Generating PEM file (Base64 Encoding) ==="
            Write-Host "                 "
            $StringBuilder = new-Object System.Text.StringBuilder
            [void]$StringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            [void]$StringBuilder.AppendLine([System.Convert]::ToBase64String($certificate,[System.Base64FormattingOptions]::InsertLineBreaks))
            [void]$StringBuilder.AppendLine("-----END CERTIFICATE-----")
            $CertString = $StringBuilder.Tostring()
            $CertString | out-file "$Filename.pem"
    
            $stream.Dispose()
            $sslStream.Dispose()

            Write-Host -Foreground Magenta "$Filename.pem is ready."

            Write-Host "                "
            Write-Host -Foreground Yellow "=== 6. Generating CER file (Binary) ==="
            if($PSVersionTable.PSVersion.Major -lt 6) {
                Set-Content -Path ".\$Filename.cer" -Encoding Byte -Value $Cert.Export('Cert')
            } else {
                Set-Content -Path ".\$Filename.cer" -AsByteStream -Value $Cert.Export('Cert')
            }

            Write-Host -Foreground Magenta "$Filename.cer is ready."
        } else {
            Write-Host "ERROR: No <STARTTLS> found" -ForegroundColor Red
        }
    }
} else {
    Write-Host -Foreground Yellow "=== 3. SSL/TLS Handshake Test ==="

    $Cert = $null
    $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

    $TcpClient.Connect($ServerName, $Port)
    $TcpStream = $TcpClient.GetStream()

    $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
    $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
    try {
        $sslStream.AuthenticateAsClient($ServerName,$CertCollection,$Protocol,$false)
    } catch {
        Write-Host -ForegroundColor Red "The client and server cannot communicate, because they do not possess a common algorithm"
        exit
    }

    # $SslStream.AuthenticateAsClient('')
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
        exit
    }

    # Save the extacted certificate to a file
    Write-Host -Foreground Yellow "=== 4. Generating PEM file (Base64 Encoding) ==="
    $Base64PEM = new-object System.Text.StringBuilder
    $Base64PEM.AppendLine("-----BEGIN CERTIFICATE-----")
    $Base64PEM.AppendLine([System.Convert]::ToBase64String($Cert.RawData, 1))
    $Base64PEM.AppendLine("-----END CERTIFICATE-----")
    $Base64PEM.ToString() | out-file "$Filename.pem"

    Write-Host -Foreground Magenta "$Filename.pem is ready."

    Write-Host "                "
    Write-Host -Foreground Yellow "=== 5. Generating CER file (Binary) ==="
        if($PSVersionTable.PSVersion.Major -lt 6) {
            Set-Content -Path ".\$Filename.cer" -Encoding Byte -Value $Cert.Export('Cert')
        } else {
            Set-Content -Path ".\$Filename.cer" -AsByteStream -Value $Cert.Export('Cert')
        }

    Write-Host -Foreground Magenta "$Filename.cer is ready."
}

Write-Host "  "
Write-Host -Foreground Yellow  "=== Final Step: Extract the public key ==="

$loc = (Get-Location).ToString()
$certFile = $loc + "\$Filename.pem"

if($PSVersionTable.PSVersion.Major -ge 7){
    $Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($certFile)
} else {
    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $Cert.Import($certFile)
}

$key = $cert.GetPublicKeyString()
Set-Content -Path ".\$Filename.PublicKey.txt" -Value $key
Write-Host -Foreground Magenta "$Filename.PublicKey.txt is ready."
Write-Host "  "
Write-Host -Foreground Red "=== complete ==="
Write-Host "  "
Get-ChildItem -Path "$Filename*"