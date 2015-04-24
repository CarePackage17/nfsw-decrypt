/*
================================
		 speed project

category: external tools
purpose: decryption of log files
author: ArmsOfSorrow
date: 08-01-2015
================================
*/

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>

void print_args(int argc, char *argv[]);
void print_usage();
void apply_cipher(char *pBuf, unsigned int len);
void work(char op, int fileCount, char* argv[]);

const char *binMode = "rb";
const char *trMode = "r";
const char *fileext = ".nfs";
		
/* build params: /EHsc /MTd /Zi /Fa decrypt.cpp */
int main(int argc, char* argv[])
{	
	//print_args(argc, argv);
	if (argc > 1)
	{
		char *pOpt = argv[1];
		
		if (*pOpt++ == '/')
		{
			switch (*pOpt)
			{
				case 'd':
				//validate file paths, decrypt files
				puts("decryption mode:\n");
				work('d', argc - 2, argv);
				break;
				
				case 'e':
				puts("encryption mode:\n");
				work('e', argc - 2, argv);
				break;
				
				case '?':
				default:
					print_usage();
				break;
			}
		}
		else
		{
			puts("Invalid first argument.\n");
			print_usage();
		}
	}
	else
	{
		puts("You didn't specify enough arguments.\n");
		print_usage();
	}
	
	return 0;
}

void print_usage()
{
	puts("Usage: /d FILES \t decrypts the specified FILES\n");
	puts("       /e FILES \t encrypts the specified FILES\n");
	puts("       /?       \t prints usage\n");
}

long file_getlength(FILE* pFile)
{
	//TODO: this isn't supposed to work in binary, although it does. change it anyway.
	fseek(pFile, 0, SEEK_END);
	long len = ftell(pFile);
	rewind(pFile);
	
	return len;
}

void file_createname(char *pSrcPath, char *pNewPath, size_t len)
{
	while (*pSrcPath++);
	while (*pSrcPath != '\\') pSrcPath--;
	pSrcPath++; //get rid of slash
	strcpy_s(pNewPath, len, pSrcPath);
	strcat_s(pNewPath, len, fileext);
}

void work(char op, int fileCount, char* argv[])
{
	if (fileCount == 0)
	{
		puts("No files specified.\n");
		return;
	}
	
	for (int i = 0; i < fileCount; ++i)
	{
		char *pFilePath = argv[i+2]; //paths start at argv[2]
		FILE *pSrcFile = nullptr;
		errno_t err;
		
			
		if (op == 'd')
			err = fopen_s(&pSrcFile, pFilePath, binMode);
		else
			err = fopen_s(&pSrcFile, pFilePath, trMode);
				
		if (!err)
		{
			long len = file_getlength(pSrcFile);
			printf("file name: %s\nfile length: %ld\n", pFilePath, len);
				
			if (len > 0)
			{
				//allocate large enough buffer, read in file contents
				char *pBuf = (char *) malloc(len);
				fread(pBuf, sizeof(char), len, pSrcFile); //nfsw treats it as one element of size len for some reason
				
				apply_cipher(pBuf, len);
				
				//create new file and save it
				FILE *pResultFile;
				size_t fnBufLen = strlen(pFilePath) + 5;
				char *pResFileName = (char *) malloc(fnBufLen);
				file_createname(pFilePath, pResFileName, fnBufLen);
				printf("result file name: %s\n", pResFileName);
				
				fopen_s(&pResultFile, pResFileName, "ab");
				fwrite(pBuf, len, sizeof(char), pResultFile);
				
				fclose(pResultFile);
				free(pResFileName);
				free(pBuf);
			}
			//close file, since we don't need it any longer
			fclose(pSrcFile);

		}
		else
		{
			printf("%s could not be opened. Make sure you entered a valid path.\n", *pFilePath);
		}
	}
}

void print_args(int argc, char *argv[])
{
	printf("argc: %d\n");
	int i = 0;
	do
	{
		printf("argv[%d] = %s\n", i, argv[i]);
		++i;
	}
	while (i < argc);
}

void apply_cipher(char* pBuf, unsigned int len)
{
	unsigned int eax, ecx = 0;
	unsigned int edi = 0x00519753;
	for (int i = 0; i < len; ++i)
	{
		eax = edi;
		eax ^= 0x1D872B41;
		ecx = eax >> 0x5;
		ecx ^= eax;
		edi = ecx << 0x1B;
		edi ^= ecx;
		ecx = 0x00B0ED68;
		edi ^= eax;
		eax = edi >> 0x17;
		*pBuf ^= (char) eax;
		++pBuf;
	}
}