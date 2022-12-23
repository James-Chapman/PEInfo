// Copyright(c) 2019-2022, James Chapman
//
// Use of this source code is governed by a BSD -
// style license that can be found in the LICENSE file or
// at https://choosealicense.com/licenses/bsd-3-clause/

#pragma warning(disable : 4996)

#include "PeFileDefs.h"
#include "PeFileReader.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

using namespace uplinkzero;

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"{\n";
    int fileCount = 1;
    for (int i = 1; i < argc; ++i)
    {
        ++fileCount;
        wchar_t* fileName = argv[i];

        std::wstring wfileNameStr(argv[i]);
        PeFileReader fileReader(fileName);
        if (!fileReader.IsPeFile())
        {
            continue;
        }

        auto coff_hdr = fileReader.GetCoffHeader();
        auto magicNum = fileReader.GetMagicNumber();
        auto certs = fileReader.GetSignCerts();

        std::wcout << L"    \"PE file\": {\n";
        std::wcout << L"        \"File name\": \"" << fileName << L"\",\n";
        std::wcout << L"        \"File data\": {\n";

        // coff_hdr.TimeDateStamp is just a DWORD with epoch time
        auto tm = std::chrono::system_clock::to_time_t(std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::duration<DWORD>(coff_hdr.TimeDateStamp))));

        std::wcout << L"            \"TimeDateStamp\": \"" << std::put_time(std::localtime(&tm), L"%Y-%m-%d %H:%M:%S %Z") << L"\",\n";
        std::wcout << L"            \"Machine type\": \"" << std::hex << "0x" << coff_hdr.Machine << L"\",\n";
        std::wcout << L"            \"Magic Number\": \"" << std::hex << "0x" << magicNum << L"\",\n";
        std::wcout << L"            \"Authenticode Signing Certificates\": [";
        size_t certCount = 0;
        for (const auto& cert : certs)
        {
            ++certCount;
            std::wcout << L"{\n";
            std::wcout << L"                \"Subject Name\": \"" << cert.SubjectName.c_str() << L"\",\n";
            std::wcout << L"                \"Issuer Name\": \"" << cert.IssuerName.c_str() << L"\",\n";
            std::wcout << L"                \"Serial Number\": \"" << cert.SerialNumber << L"\",\n";
            std::wcout << L"                \"Subject Key Identifier\": \"" << cert.SubjectKeyIdentifier << L"\"\n";
            std::wcout << L"            }";
            if (certCount != certs.size())
            {
                std::wcout << L",\n";
            }
        }
        std::wcout << L"]\n";

        std::wcout << L"        }\n";
        std::wcout << L"    }";
        if (fileCount != argc)
        {
            std::wcout << L",\n";
        }
        else
        {
            std::wcout << L"\n";
        }
    }
    std::wcout << L"}\n";
    return 0;
}
