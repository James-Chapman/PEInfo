# PEInfo

Get information from PE files, including authenticode signing certificate data.

```Text
C:\Users\User>PEInfo.exe "C:\Program Files\7-Zip\7z.exe" "C:\Program Files\Adobe\
Acrobat DC\Acrobat\Acrobat.exe" "C:\Program Files\Google\Chrome\Application\chrome.exe"
{
    "PE file name": "C:\Program Files\7-Zip\7z.exe",
    "PE file data": {
        "TimeDateStamp": "2020-08-08 20:00:00 GMT Summer Time",
        "Machine type": 0x8664,
        "Magic Number": 0x20b,
        "Authenticode Signing Certificates": []
    },
    "PE file name": "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    "PE file data": {
        "TimeDateStamp": "2022-11-14 18:38:45 GMT Standard Time",
        "Machine type": 0x8664,
        "Magic Number": 0x20b,
        "Authenticode Signing Certificates": [{
            "Subject Name": "Adobe Inc.",
            "Issuer Name": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
            "Serial Number": "045296f8fcd829a75dc94294f5a415a4",
            "Subject Key Identifier": "66c6c3856caf75d36ff8f5c472181b4863e45986"
        }]
    },
    "PE file name": "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "PE file data": {
        "TimeDateStamp": "2022-12-12 18:07:40 GMT Standard Time",
        "Machine type": 0x8664,
        "Magic Number": 0x20b,
        "Authenticode Signing Certificates": [{
            "Subject Name": "Google LLC",
            "Issuer Name": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
            "Serial Number": "0e4418e2dede36dd2974c3443afb5ce5",
            "Subject Key Identifier": "47a58d30595525187338f85b7f8235fc919ce3fc"
        }]
    }
}
```
