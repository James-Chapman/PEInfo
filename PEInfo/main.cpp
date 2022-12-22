// Copyright 2022 James Chapman
//
// Use of this source code is governed by a BSD -
// style license that can be found in the LICENSE file or
// at https://developers.google.com/open-source/licenses/bsd

#pragma warning(disable : 4996)

#include "PeFileDefs.h"
#include "PeFileReader.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>

using namespace uplinkzero;

int main(int argc, wchar_t* argv[])
{
    wchar_t* fileName = argv[1];
    std::wstring fileNameStr(fileName);
    PeFileReader fileReader(fileName);
    if (!fileReader.IsPeFile())
    {
        return 1;
    }

    auto coff_hdr = fileReader.GetCoffHeader();
    auto magicNum = fileReader.GetMagicNumber();
    auto opt_hdr = fileReader.GetOptionalHeader();
    auto certs = fileReader.GetSignCerts();

    //std::wcout << L"Info for " << fileName << L"\n";
    //std::wcout << L"Info for " << fileNameStr << L"\n";

    for (const auto& cert : certs)
    {
        std::wcout << L"{\n";
        std::wcout << L"    \"Subject Name\": \"" << cert.SubjectName.c_str() << L"\"\n";
        std::wcout << L"    \"Issuer Name\": \"" << cert.IssuerName.c_str() << L"\"\n";
        std::wcout << L"    \"Serial Number\": \"" << cert.SerialNumber << L"\"\n";
        std::wcout << L"    \"Subject Key Identifier\": \"" << cert.SubjectKeyIdentifier << L"\"\n";
        std::wcout << L"}\n";
    }

    return 0;
}
