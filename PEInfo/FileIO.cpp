/**********************************************************
*
* Make file i/o easy.
*
*
***********************************************************/

#include "FileIO.hpp"
#include <cstring>

using namespace Uplinkzero;

FileIO::FileIO(const char * path, bool write /*= false*/, bool read/* = true*/)
	: m_handle(nullptr)
	, m_fileSize(0)
	, m_cursor(0)
	, m_error(false)
	, m_openRead(false)
	, m_openWrite(false)
	, m_filePath(path)
{
	if (write && read)
	{
		m_handle = fopen(path, "wb+");
		if (m_handle != nullptr)
		{
			m_openRead = true;
			m_openWrite = true;
		}
	}
	else if (write)
	{
		m_handle = fopen(path, "wb");
		if (m_handle != nullptr)
		{
			m_openRead = false;
			m_openWrite = true;
		}
	}
	else
	{
		m_handle = fopen(path, "rb");
		if (m_handle != nullptr)
		{
			m_openRead = true;
			m_openWrite = false;
		}
	}
	if (m_handle == nullptr)
		m_error = true;
}


FileIO::~FileIO()
{
	if (m_handle != nullptr)
	{
		fflush(m_handle);
		fclose(m_handle);
	}
	if (m_handle != nullptr)
		m_error = true;
}


size_t FileIO::GetFileSize()
{
	if (m_error == true)
		return 0;

	if (m_handle == nullptr)
	{
		m_error = true;
		return 0;
	}

	size_t current = 0;
#ifdef _WIN32
	current = _ftelli64(m_handle);
	_fseeki64(m_handle, 0, SEEK_END);
	m_fileSize = _ftelli64(m_handle);
	if (m_fileSize == -1L)
		printf("errno: %d\n", errno);
	_fseeki64(m_handle, 0, current);
#else
	current = ftello64(m_handle);
	fseeko64(m_handle, 0, SEEK_END);
	m_fileSize = ftello64(m_handle);
	if (m_fileSize == -1L)
		printf("errno: %d\n", errno);
	fseeko64(m_handle, 0, current);
#endif
	return m_fileSize;
}


size_t FileIO::ReadBlock(BYTE * pBuffer, size_t size)
{
	if (m_error == true)
		return 0;

	if (m_handle == nullptr)
	{
		m_error = true;
		return 0;
	}

	if (m_openRead == false)
	{
		size_t current = m_fileSize = ftell(m_handle);
		fclose(m_handle);
		m_handle = fopen(reinterpret_cast<const char *>(m_filePath), "rb");
		if (m_handle == nullptr)
		{
			m_error = true;
			return 0;
		}
	}
	size_t read = 0;
	read = fread(pBuffer, 1, size, m_handle);
	m_cursor += read;
	return read;
}


size_t FileIO::WriteBlock(BYTE * pBuffer, size_t size)
{
	if (m_error == true)
		return 0;

	if (m_handle == nullptr)
	{
		m_error = true;
		return 0;
	}

	if (m_openWrite == false)
	{
		size_t current = m_fileSize = ftell(m_handle);
		fclose(m_handle);
		m_handle = fopen(reinterpret_cast<const char *>(m_filePath), "wb");
		if (m_handle == nullptr)
		{
			m_error = true;
			return 0;
		}
	}
	size_t written = 0;
	written = fwrite(pBuffer, 1, size, m_handle);
	m_cursor += written;
	return written;
}


/**
* Dangerous! strlen assumes NUL termination. Should only be used with strings.
*/
void Uplinkzero::FileIO::operator<<(const char * string)
{
	size_t size = strlen(reinterpret_cast<const char *>(string));
	fwrite(string, 1, size, m_handle);
}


const char * FileIO::GetFilePath()
{
	return m_filePath;
}


const char * FileIO::GetFileName()
{
#ifdef _WIN32
	constexpr char DIRSEP = '\\';
#else
	constexpr char DIRSEP = '/';
#endif
	const char * pLastDirSep = nullptr;
	pLastDirSep = strrchr(m_filePath, DIRSEP);
	if (pLastDirSep == nullptr)
		return m_filePath;
	else
		return pLastDirSep;
}