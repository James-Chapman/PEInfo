#pragma once
#ifndef FILEIO_HPP
#define FILEIO_HPP

#pragma warning(disable : 4996)

#include <cstdio>

#include "common_defs.h"

namespace Uplinkzero
{
	typedef enum _FileIO_Error
	{
		FE_OK,
		FE_OPENERROR,
		FE_READERROR,
		FE_WRITEERROR
	} FileIO_Error;

	class FileIO
	{
	public:
		FileIO(const char * path, bool write = false, bool read = true);
		virtual ~FileIO();

		size_t GetFileSize();
		size_t ReadBlock(BYTE * pBuffer, size_t size);
		size_t WriteBlock(BYTE * pBuffer, size_t size);

		void operator<< (const char * string); // Dangerous! Assumes NUL termination. Should only be used with strings.

		const char * GetFileName();
		const char * GetFilePath();

	private:
		FILE * m_handle;
		size_t m_fileSize;
		size_t m_cursor;
		bool m_error;
		bool m_openRead;
		bool m_openWrite;
		const char * m_filePath;
	};

}




#endif // FILEIO_HPP