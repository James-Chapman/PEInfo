// Copyright(c) 2019-2022, James Chapman
//
// Use of this source code is governed by a BSD -
// style license that can be found in the LICENSE file or
// at https://choosealicense.com/licenses/bsd-3-clause/

#pragma once

#include "CommonDefs.h"

#include <Windows.h>
#include <string>
#include <vector>

namespace uplinkzero
{

struct COFF_Header
{
    WORD Machine{0};
    WORD NumberOfSections{0};
    DWORD TimeDateStamp{0};
    DWORD PointerToSymbolTable{0};
    DWORD NumberOfSymbols{0};
    WORD SizeOfOptionalHeader{0};
    WORD Characteristics{0};
};

struct Optional_Header
{
    // Optional Header Standard Fields (Image Only)
    WORD Magic{0};
    BYTE MajorLinkerVersion{0};
    BYTE MinorLinkerVersion{0};
    DWORD SizeOfCode{0};
    DWORD SizeOfInitializedData{0};
    DWORD SizeOfUninitializedData{0};
    DWORD AddressOfEntryPoint{0};
    DWORD BaseOfCode{0};
    DWORD BaseOfData{0};

    // Optional Header Windows Specific Fields(Image Only)
    union {
        DWORD ImageBaseDw;
        QWORD ImageBaseQw;
    };
    DWORD SectionAlignment{0};
    DWORD FileAlignment{0};
    WORD MajorOperatingSystemVersion{0};
    WORD MinorOperatingSystemVersion{0};
    WORD MajorImageVersion{0};
    WORD MinorImageVersion{0};
    WORD MajorSubsystemVersion{0};
    WORD MinorSubsystemVersion{0};
    DWORD Win32VersionValue{0};
    DWORD SizeOfImage{0};
    DWORD SizeOfHeaders{0};
    DWORD CheckSum{0};
    DWORD Subsystem{0};
    DWORD DllCharacteristics{0};
    union {
        DWORD SizeOfStackReserveDw;
        QWORD SizeOfStackReserveQw;
    };
    union {
        DWORD SizeOfStackCommitDw;
        QWORD SizeOfStackCommitQw;
    };

    union {
        DWORD SizeOfHeapReserveDw;
        QWORD SizeOfHeapReserveQw;
    };
    union {
        DWORD SizeOfHeapCommitDw;
        QWORD SizeOfHeapCommitQw;
    };
    DWORD LoaderFlags{0};
    DWORD NumberOfRvaAndSizes{0};

    // Data directories
    IMAGE_DATA_DIRECTORY ExportTable{0};
    IMAGE_DATA_DIRECTORY ImportTable{0};
    IMAGE_DATA_DIRECTORY ResourceTable{0};
    IMAGE_DATA_DIRECTORY ExceptionTable{0};
    IMAGE_DATA_DIRECTORY CertificateTable{0};
    IMAGE_DATA_DIRECTORY BaseRelocationTable{0};
    IMAGE_DATA_DIRECTORY DebugData{0};
    IMAGE_DATA_DIRECTORY Architecture{0};
    IMAGE_DATA_DIRECTORY GlobalPtr{0};
    IMAGE_DATA_DIRECTORY TlsTable{0};
    IMAGE_DATA_DIRECTORY LoadConfigTable{0};
    IMAGE_DATA_DIRECTORY BoundImportTable{0};
    IMAGE_DATA_DIRECTORY ImportAddressTable{0};
    IMAGE_DATA_DIRECTORY DelayImportDescriptor{0};
    IMAGE_DATA_DIRECTORY ClrRuntimeHeader{0};
    IMAGE_DATA_DIRECTORY ReservedTable{0};
};

struct Certificate_Data
{
    std::wstring SubjectName{};
    std::wstring IssuerName{};
    std::wstring SerialNumber{};
    std::wstring SubjectKeyIdentifier{};

    std::wstring TimeStampSubjectName{};
    std::wstring TimeStampIssuerName{};
    std::wstring TimeStampSerialNumber{};
    std::wstring TimeStampSubjectKeyIdentifier{};
};

enum PEMagicNumber
{
    PE32 = 0x10b,
    PE32plus = 0x20b
};

} // namespace uplinkzero