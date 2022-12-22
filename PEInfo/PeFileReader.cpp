// Copyright 2022 James Chapman
//
// Use of this source code is governed by a BSD -
// style license that can be found in the LICENSE file or
// at https://developers.google.com/open-source/licenses/bsd

#include "PeFileReader.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

// Windows specific headers
#include <ImageHlp.h>
#include <WinTrust.h>
#include <Windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ImageHlp.lib")

namespace uplinkzero
{

constexpr auto PESignatureLocationOffset{0x3c};
constexpr auto PEOptionalHeaderLocationOffset{0x14}; // 20 bytes
DWORD PESignatureLocation{0x0};                      // Gets set later
DWORD PEOptionalHeaderLocation{0x0};                 // Gets set later

PeFileReader::PeFileReader(std::wstring filePath) : m_filePath{filePath}, m_fileHandle{nullptr}
{
    m_fileHandle = ::CreateFile(reinterpret_cast<LPCSTR>(m_filePath.c_str()), FILE_READ_DATA, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
}

PeFileReader::~PeFileReader()
{
    ::CloseHandle(m_fileHandle);
}

bool PeFileReader::IsPeFile()
{
    BYTE dosHeader[2];
    ::SetFilePointer(m_fileHandle, 0, NULL, FILE_BEGIN);
    ::ReadFile(m_fileHandle, dosHeader, 2, NULL, NULL);
    if (dosHeader[0] != 0x4d || // M
        dosHeader[1] != 0x5a)   // Z
    {
        return false;
    }

    ::SetFilePointer(m_fileHandle, PESignatureLocationOffset, NULL, FILE_BEGIN);
    ::ReadFile(m_fileHandle, &PESignatureLocation, 2, NULL, NULL);

    BYTE peHeader[4];
    ::SetFilePointer(m_fileHandle, PESignatureLocation, NULL, FILE_BEGIN);
    ::ReadFile(m_fileHandle, peHeader, 4, NULL, NULL);

    if (peHeader[0] != 0x50 || // P
        peHeader[1] != 0x45 || // E
        peHeader[2] != 0x0 ||  // 0
        peHeader[3] != 0x0)    // 0
    {
        return false;
    }

    PEOptionalHeaderLocation = PESignatureLocation + PEOptionalHeaderLocationOffset;
    return true;
}

COFF_Header PeFileReader::GetCoffHeader()
{
    if (!IsPeFile())
    {
        throw std::runtime_error("Not a PE file.");
    }

    COFF_Header coff;
    ::SetFilePointer(m_fileHandle, PESignatureLocation, NULL, FILE_BEGIN);
    ::ReadFile(m_fileHandle, &coff.Machine, 2, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.NumberOfSections, 2, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.TimeDateStamp, 4, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.PointerToSymbolTable, 4, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.NumberOfSymbols, 4, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.SizeOfOptionalHeader, 2, NULL, NULL);
    ::ReadFile(m_fileHandle, &coff.Characteristics, 2, NULL, NULL);

    return coff;
}

PEMagicNumber PeFileReader::GetMagicNumber()
{
    DWORD magicNum{0};
    if (!IsPeFile())
    {
        throw std::runtime_error("Not a PE file.");
    }

    ::SetFilePointer(m_fileHandle, PEOptionalHeaderLocation, NULL, FILE_BEGIN);
    ::ReadFile(m_fileHandle, &magicNum, 2, NULL, NULL);

    return static_cast<PEMagicNumber>(magicNum);
}

Optional_Header PeFileReader::GetOptionalHeader()
{
    if (!IsPeFile())
    {
        throw std::runtime_error("Not a PE file.");
    }

    Optional_Header optHdr;
    ::SetFilePointer(m_fileHandle, PEOptionalHeaderLocation, NULL, FILE_BEGIN);
    {
        // Update Optional Header Standard Fields (Image Only)
        ::ReadFile(m_fileHandle, &optHdr.Magic, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MajorLinkerVersion, 1, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MinorLinkerVersion, 1, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.SizeOfCode, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.SizeOfInitializedData, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.SizeOfUninitializedData, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.AddressOfEntryPoint, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.BaseOfCode, 4, NULL, NULL);

        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            // Field only present in PE32 files
            ::ReadFile(m_fileHandle, &optHdr.BaseOfData, 4, NULL, NULL);
        }
    }

    {
        // Update Optional Header Windows Specific Fields
        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            ::ReadFile(m_fileHandle, &optHdr.ImageBaseDw, 4, NULL, NULL);
        }
        else
        {
            ::ReadFile(m_fileHandle, &optHdr.ImageBaseQw, 8, NULL, NULL);
        }
        ::ReadFile(m_fileHandle, &optHdr.SectionAlignment, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.FileAlignment, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MajorOperatingSystemVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MinorOperatingSystemVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MajorImageVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MinorImageVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MajorSubsystemVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.MinorSubsystemVersion, 2, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.Win32VersionValue, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.SizeOfImage, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.SizeOfHeaders, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.CheckSum, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.Subsystem, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.DllCharacteristics, 4, NULL, NULL);
        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfStackReserveDw, 4, NULL, NULL);
        }
        else
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfStackReserveQw, 8, NULL, NULL);
        }

        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfStackCommitDw, 4, NULL, NULL);
        }
        else
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfStackCommitQw, 8, NULL, NULL);
        }
        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfHeapReserveDw, 4, NULL, NULL);
        }
        else
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfHeapReserveQw, 8, NULL, NULL);
        }
        if (optHdr.Magic == static_cast<WORD>(PEMagicNumber::PE32))
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfHeapCommitDw, 4, NULL, NULL);
        }
        else
        {
            ::ReadFile(m_fileHandle, &optHdr.SizeOfHeapCommitQw, 8, NULL, NULL);
        }
        ::ReadFile(m_fileHandle, &optHdr.LoaderFlags, 4, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.NumberOfRvaAndSizes, 4, NULL, NULL);
    }

    {
        // Update Data Directories
        ::ReadFile(m_fileHandle, &optHdr.ExportTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ImportTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ResourceTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ExceptionTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.CertificateTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.BaseRelocationTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.DebugData, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.Architecture, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.GlobalPtr, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.TlsTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.LoadConfigTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.BoundImportTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ImportAddressTable, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.DelayImportDescriptor, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ClrRuntimeHeader, 8, NULL, NULL);
        ::ReadFile(m_fileHandle, &optHdr.ReservedTable, 8, NULL, NULL);
    }

    return optHdr;
}

std::vector<Certificate_Data> PeFileReader::GetSignCerts()
{
    std::vector<Certificate_Data> retval{};

    DWORD dwCertCount = 0;

    { // Enumerate all the embedded certificates
        if (!::ImageEnumerateCertificates(m_fileHandle, CERT_SECTION_TYPE_ANY, &dwCertCount, NULL, 0))
        {
            std::cout << "ImageEnumerateCertificates error: " << GetLastError() << std::endl;
            return {};
        }
    }

    for (DWORD i = 0; i < dwCertCount; ++i)
    {
        retval.push_back(GetCertAtIndex(i));
    }
    return retval;
}

Certificate_Data PeFileReader::GetCertAtIndex(DWORD i)
{
    Certificate_Data certData{};
    char* pCertBuf{nullptr};
    PCCERT_CONTEXT pCertContext{nullptr};
    WIN_CERTIFICATE certHeader;
    WIN_CERTIFICATE* pCert{nullptr};
    PCMSG_SIGNER_INFO pSignerInfo{nullptr};
    PCMSG_SIGNER_INFO pCounterSignerInfo{nullptr};

    certHeader.dwLength = 0;
    certHeader.wRevision = WIN_CERT_REVISION_1_0;
    if (!::ImageGetCertificateHeader(m_fileHandle, i, &certHeader))
    {
        std::cout << "ImageGetCertificateHeader error: " << GetLastError() << std::endl;
        return {};
    }

    DWORD dwCertLen = certHeader.dwLength;
    pCertBuf = new char[sizeof(WIN_CERTIFICATE) + dwCertLen];
    pCert = (WIN_CERTIFICATE*)pCertBuf;
    pCert->dwLength = dwCertLen;
    pCert->wRevision = WIN_CERT_REVISION_1_0;
    if (!::ImageGetCertificateData(m_fileHandle, i, pCert, &dwCertLen))
    {
        std::cout << "ImageGetCertificateData error: " << GetLastError() << std::endl;
        return {};
    }

    { // Verify signature
        DWORD dwDecodeSize = 0;
        CRYPT_VERIFY_MESSAGE_PARA para = {0};
        para.cbSize = sizeof(para);
        para.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

        if (!::CryptVerifyMessageSignature(&para, i, pCert->bCertificate, pCert->dwLength, NULL, &dwDecodeSize,
                                           &pCertContext))
        {
            std::cout << "CryptVerifyMessageSignature error: " << GetLastError() << std::endl;
            return {};
        }
    }

    { // Get certificate Subject Name
        DWORD dwSubjectSize = ::CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
        if (dwSubjectSize <= 0)
        {
            std::cout << "CertGetNameStringW error: " << GetLastError() << std::endl;
            return {};
        }

        std::array<wchar_t, 256> buf{0x0};

        ::CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, buf.data(), dwSubjectSize);
        certData.SubjectName = std::wstring(buf.begin(), buf.end());
    }

    { // Get certificate Issuer Name
        DWORD dwIssuerSize =
            ::CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
        if (dwIssuerSize <= 0)
        {
            std::cout << "CertGetNameStringW error: " << GetLastError() << std::endl;
            return {};
        }
        std::array<wchar_t, 256> buf{0x0};

        ::CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, buf.data(),
                             dwIssuerSize);
        certData.IssuerName = std::wstring(buf.begin(), buf.end());
    }

    { // Get certificate serial number
        DWORD dwData = pCertContext->pCertInfo->SerialNumber.cbData;
        std::wstringstream serialss;
        serialss << std::hex;
        for (DWORD j = 0; j < dwData; ++j)
        {
            serialss << std::setw(2) << std::setfill(L'0')
                     << static_cast<int>(pCertContext->pCertInfo->SerialNumber.pbData[dwData - (j + 1)]);
        }
        certData.SerialNumber = serialss.str();
    }

    { // Get certificate Subject Key Identifierta
        DWORD dwData{64};
        BYTE data[64];
        ::CertGetCertificateContextProperty(pCertContext, CERT_KEY_IDENTIFIER_PROP_ID, &data, &dwData);
        std::wstringstream skiss;
        skiss << std::hex;
        for (DWORD j = 0; j < dwData; ++j)
        {
            skiss << std::setw(2) << std::setfill(L'0') << (int)data[j];
        }
        certData.SubjectKeyIdentifier = skiss.str();
    }

    if (pCertContext)
    {
        CertFreeCertificateContext(pCertContext);
    }

    return certData;
}

} // namespace uplinkzero