# Get-X.509-Certificate
Retrieve X.509 certificate from remote server

This tool can download the X.509 certificate from remote server and save it to a file in PEM format. It can also extract the public key from the remote certificate.

usage: Get-X509.Cert.ps1 SERVER_NAME [PORT_NUMBER] [-SMTP] [-tv PROTOCOL_VERSION]

       -tv   : TLS version, possible value: SSLv2,SSLv3,TLSv10,TLSv11,TLSv12,TLSv13. Default is TLSv12.
       
       -SMTP : For SMTP server

Screenshot:

![image](https://user-images.githubusercontent.com/57880343/177472650-d91e910f-5436-41ed-9b88-63fb1ed4fed4.png)
![image](https://user-images.githubusercontent.com/57880343/177473477-e54f60ca-4ab2-4eb9-9c9f-40b6786096d7.png)
![image](https://user-images.githubusercontent.com/57880343/177472726-d824a887-98c2-4b1f-b355-5a563a023fba.png)
![image](https://user-images.githubusercontent.com/57880343/177472777-0afa023b-27d9-4733-a8b6-a7ba401a1387.png)

![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
