// Copyright(c) 2019-2022, James Chapman
//
// Use of this source code is governed by a BSD -
// style license that can be found in the LICENSE file or
// at https://choosealicense.com/licenses/bsd-3-clause/

#pragma once

#include "PeFileDefs.h"

#include <memory>

namespace uplinkzero
{

class PeFileReader
{
public:
    explicit PeFileReader(std::wstring filePath);
    virtual ~PeFileReader();

    bool IsPeFile();
    COFF_Header GetCoffHeader();
    PEMagicNumber GetMagicNumber();
    Optional_Header GetOptionalHeader();
    std::vector<Certificate_Data> GetSignCerts();

private:
    Certificate_Data GetCertAtIndex(DWORD i);
    std::wstring m_filePath{};
    HANDLE m_fileHandle{};
};

} // namespace uplinkzero
