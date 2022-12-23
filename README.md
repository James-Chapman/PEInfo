# PEInfo

## About 

Threat researchers typically want all kinds of information from PE files to help write better detections. This tool is aimed at that community and allows you to extract information from PE files, including authenticode signing certificate data. Only a fraction of the information being extracted is printed to stdout. If I get a boost of inspiration in the future I'll add more data to the output.

## Building

This was written on Windows, for WIndows, to read Windows Portable Executable (PE) files. It uses Windows APIs. You'll therefore need the Windows SDK and MSVC compiler. Visual Studio 2022 solution file is provided. There are probably ways to make it build in Visual Studio Code and possibly even using Clang/LLVM compiler.

## Usage

```Text
C:\Users\User>PEInfo.exe "C:\Program Files\7-Zip\7z.exe" "C:\Program Files\Adobe\
Acrobat DC\Acrobat\Acrobat.exe" "C:\Program Files\Google\Chrome\Application\chrome.exe"
{
    "PE file": {
        "File name": "C:\Program Files\7-Zip\7z.exe",
        "File data": {
            "TimeDateStamp": "2020-08-08 20:00:00 GMT Summer Time",
            "Machine type": "0x8664",
            "Magic Number": "0x20b",
            "Authenticode Signing Certificates": []
        }
    },
    "PE file": {
        "File name": "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        "File data": {
            "TimeDateStamp": "2022-11-14 18:38:45 GMT Standard Time",
            "Machine type": "0x8664",
            "Magic Number": "0x20b",
            "Authenticode Signing Certificates": [{
                "Subject Name": "Adobe Inc.",
                "Issuer Name": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
                "Serial Number": "045296f8fcd829a75dc94294f5a415a4",
                "Subject Key Identifier": "66c6c3856caf75d36ff8f5c472181b4863e45986"
            }]
        }
    },
    "PE file": {
        "File name": "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "File data": {
            "TimeDateStamp": "2022-12-12 18:07:40 GMT Standard Time",
            "Machine type": "0x8664",
            "Magic Number": "0x20b",
            "Authenticode Signing Certificates": [{
                "Subject Name": "Google LLC",
                "Issuer Name": "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
                "Serial Number": "0e4418e2dede36dd2974c3443afb5ce5",
                "Subject Key Identifier": "47a58d30595525187338f85b7f8235fc919ce3fc"
            }]
        }
    }
}
```
