

#include "PEFile.hpp"
using namespace uplinkzero;

PEFile::PEFile()
	: m_PEHeader(nullptr)
	, m_COFFFields(nullptr)
	, m_WindowsFields(nullptr)
	, m_DataDirectories(nullptr)
	, m_SectionTable(nullptr)
{

}

PEFile::~PEFile()
{

}

