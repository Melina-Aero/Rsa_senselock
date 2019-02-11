/*****************************************************************************************
*  Copyright (c) 2004, Beijing Senselock Data Security Centre
*  All rights reserved.
*
*  Filename：sample_27_win32.c
*          
*  Briefs：  The purpose of this snippet is to demonstrate how to invoke the written-in  
*            SenseLock EL executables to do the sign/verify/en/decrypt operation for the 
*            objective data.  
*  History:        
*  --------------------------------------------------------        
*            10/28/2004 v1.0.0.0 Lihua created
*            11/04/2004 v1.0.0.1 Lihua modified 
*            11/08/2004 v1.0.0.2 Lihua modified   
*******************************************************************************************/

#include <stdio.h>
#include <conio.h>
#include <assert.h>

#include "sense4.h"
#include "..\..\inc\win32\crypt2.h"
#include "..\..\inc\win32\ses_err_msg.h" /*for debug purpose only*/
#include "..\..\common\common.h"

#include "..\inc\sample_27.h"
#include<locale.h>

/* global variables definition */
SENSE4_CONTEXT stS4Ctx = {0};
unsigned long dwResult = 0;
unsigned long dwBytesReturned = 0;

IO_PACKAGE stDataPkgIn = {0};
IO_PACKAGE stDataPkgOut = {0};


#define S4_EXE_FILE_ID "ef27"

/* for debug purpose only : handle results returned by stDataPkgOut.tag */
void HandleError(unsigned char bErrCode, unsigned char *pbErrInfo)
{
	switch(bErrCode)
	{
	case ERR_SUCCESS:
		printf("Success!\n");
		break;
	case ERR_SES:
		printf("Error during SES Execution :\n%s\n", SesErrMsgs[*pbErrInfo]);
		break;
	case ERR_INVALID_PARAMETER:
		printf("Invalid input,pls check your input data\n");
		break;
	case ERR_INCORRECT_SIGNATURE:
		printf("Incorrect signature!\n");
		break;
	default:
		printf("Undefined error code!\n");
		break;
	}
	return;
}

/* check result for S4Execute(...) */
unsigned long CheckS4ExecutionResult(unsigned long dwResult,unsigned long dwBytesReturned,unsigned char tag)
{
	
	if (dwResult != S4_SUCCESS) 
	{
		printf("S4 Execution failed! <error code: 0x%08x>\n", dwResult);
		return 0;
	}
	
	if (dwBytesReturned < 2)
	{
		printf("Invalid data package returned!\n");
		return 0;
	}
	
	if (tag != ERR_SUCCESS)
	{
		HandleError(stDataPkgOut.tag, stDataPkgOut.buff);
		return 0;
	}
	return 1;
}


/* Make signature according to PKCS#1 */
unsigned long make_signature(unsigned short fid, unsigned char dgst_alg, 
						 unsigned char *in, int inlen, 
						 unsigned char *out, int *outlen, SENSE4_CONTEXT *ps4ctx, DWORD dwBytesReturned)
{
	RSA_BLOCK stRsaBlk = {0};
	
	assert(NULL != out && NULL != outlen && NULL != in);
	
	if (DA_MD5 == dgst_alg)
	{
		if (inlen != MD5_BLOCK_LEN) 
		{
			printf("Invalid digest length!\n");
			return 0;
		}
	}else if (DA_SHS == dgst_alg) 
	{
		if (inlen != SHA1_BLOCK_LEN)
		{
			printf("Invalid digest length!\n");
			return 0;
		}
	}else
	{
		printf("Input hash algorithm not supportted currently!\n");
		return 0;
	}
	if (*outlen < RSA_BLOCK_LEN) 
	{
		printf("insufficient out-buffer size!\n");
		return 0; 
	}
	stRsaBlk.fid = fid;
	stRsaBlk.len = inlen;
	stRsaBlk.dgst_alg = dgst_alg;
	memcpy(stRsaBlk.buff,in,inlen);
	
	stDataPkgIn.tag = CMD_SIGN;
	/* for efficiency, only tranfer useful data into SenseLock EL device */
	stDataPkgIn.len = sizeof(RSA_BLOCK)-sizeof(stRsaBlk.buff) + stRsaBlk.len;
	memcpy(stDataPkgIn.buff,&stRsaBlk,stDataPkgIn.len);
	
	dwResult = S4Execute(ps4ctx, S4_EXE_FILE_ID, &stDataPkgIn, 
						IO_PACKAGE_HEADER_SIZE+stDataPkgIn.len,
						&stDataPkgOut, sizeof(IO_PACKAGE), &dwBytesReturned);
	if (!CheckS4ExecutionResult(dwResult, dwBytesReturned, stDataPkgOut.tag))
	{
		return 0;
	}
	*outlen = stDataPkgOut.len;
	memcpy(out,stDataPkgOut.buff,stDataPkgOut.len);
    return 1;

}

/* Verify signature according to PKCS#1 */
unsigned long verify_signature(unsigned short fid, unsigned char dgst_alg, 
					 unsigned char *dgst, int dgst_len, 
					 unsigned char *sig, int sig_len, SENSE4_CONTEXT *ps4ctx, DWORD dwBytesReturned)
{
	RSA_VERIFY_BLOCK stRsaVBlk = {0};
	
	assert(NULL != dgst && NULL != sig );
	
	if (DA_MD5 == dgst_alg)
	{
		if (dgst_len != MD5_BLOCK_LEN) 
		{
			printf("Invalid digest length!\n");
			return 0;
		}
	}else if (DA_SHS == dgst_alg) 
	{
		if (dgst_len != SHA1_BLOCK_LEN)
		{
			printf("Invalid digest length!\n");
			return 0;
		}
	}else
	{
		printf("Input hash algorithm not supportted currently!\n");
		return 0;
	}
	if (sig_len != RSA_BLOCK_LEN) 
	{
		printf("Invalid signature block length");
		return 0; 
	}
	
	stRsaVBlk.fid = fid;
	stRsaVBlk.dgst_alg = dgst_alg;
	memcpy(stRsaVBlk.dgst,dgst,dgst_len);
	stRsaVBlk.dgst_len = dgst_len;
	/* copy signature to the block */
	memcpy(stRsaVBlk.sig,sig,sig_len);
	stRsaVBlk.sig_len = sig_len;

	stDataPkgIn.tag = CMD_VERIFY;
	stDataPkgIn.len = sizeof(RSA_VERIFY_BLOCK);
	memcpy(stDataPkgIn.buff,&stRsaVBlk,sizeof(RSA_VERIFY_BLOCK));
	
	
	dwResult = S4Execute(ps4ctx, S4_EXE_FILE_ID, &stDataPkgIn,
						IO_PACKAGE_HEADER_SIZE+stDataPkgIn.len,
						&stDataPkgOut, sizeof(IO_PACKAGE), &dwBytesReturned);
	if (!CheckS4ExecutionResult(dwResult, dwBytesReturned, stDataPkgOut.tag))
	{
		return 0;
	}
    return 1;
}

/* RSA encryption according to PKCS#1 */
unsigned long rsa_encrypt(unsigned short fid,
				  unsigned char *in, int inlen, 
				  unsigned char *out, int *outlen, SENSE4_CONTEXT *ps4ctx, DWORD dwBytesReturned)
{
	RSA_BLOCK stRsaBlk = {0};
	
	assert(NULL != out && NULL != outlen && NULL != in);
	
	if (inlen > RSA_BLOCK_LEN - 11) 
	{
		printf("Invalid plaintext length!\n");
		return 0;
	}
	if (*outlen < RSA_BLOCK_LEN) 
	{
		printf("Insufficient out-buffer size!\n");
		return 0;
	}
	/* Assemble data block for encryption. */
	stRsaBlk.fid = fid;
	stRsaBlk.len = inlen;
	memcpy(stRsaBlk.buff, in, inlen);
	
	/* Assemble IO package */
	stDataPkgIn.tag = CMD_ENCRYPT;
	
	/* for efficiency, only transfer useful data to SenseLock EL device */
	stDataPkgIn.len = sizeof(RSA_BLOCK) - sizeof(stRsaBlk.buff) + stRsaBlk.len;
	memcpy(stDataPkgIn.buff, &stRsaBlk, stDataPkgIn.len);
	
	dwResult = S4Execute(ps4ctx, S4_EXE_FILE_ID, &stDataPkgIn, 
						IO_PACKAGE_HEADER_SIZE+stDataPkgIn.len, 
						&stDataPkgOut, sizeof(IO_PACKAGE), &dwBytesReturned);
	if (!CheckS4ExecutionResult(dwResult, dwBytesReturned, stDataPkgOut.tag))
	{
		return 0;
	}
	*outlen = stDataPkgOut.len;
	memcpy(out,stDataPkgOut.buff,stDataPkgOut.len);
	return 1;
}

/* RSA decryption according to PKCS#1 */
unsigned long rsa_decrypt(unsigned short fid,
				  unsigned char *in, int inlen, 
				  unsigned char *out, int *outlen, SENSE4_CONTEXT *ps4ctx, DWORD dwBytesReturned)
{
	RSA_BLOCK stRsaBlk = {0};	
	
	assert(NULL != out && NULL != outlen && NULL != in);
	
	if (inlen != RSA_BLOCK_LEN) 
	{
		printf("Invalid ciphertext block length");
		return 0; 
	}
	
	stRsaBlk.fid = fid;
	stRsaBlk.len = inlen;
	memcpy(stRsaBlk.buff, in, inlen);
	
	stDataPkgIn.tag = CMD_DECRYPT;
	stDataPkgIn.len = sizeof(RSA_BLOCK)-sizeof(stRsaBlk.buff) + stRsaBlk.len;
	memcpy(stDataPkgIn.buff, &stRsaBlk, stDataPkgIn.len);
	
	dwResult = S4Execute(ps4ctx, S4_EXE_FILE_ID, &stDataPkgIn, 
						IO_PACKAGE_HEADER_SIZE+stDataPkgIn.len,
						&stDataPkgOut, sizeof(IO_PACKAGE), &dwBytesReturned);
	if (!CheckS4ExecutionResult(dwResult, dwBytesReturned, stDataPkgOut.tag))
	{
		return 0;
	}
	if (*outlen < stDataPkgOut.len)
	{
		printf("Insufficient out-buffer size!\n");
		return 0;
	}
    *outlen = stDataPkgOut.len;
	memcpy(out,stDataPkgOut.buff,stDataPkgOut.len);
	return 1;
	
}

SENSE4_CONTEXT *ks4ctx;

//int main(int argc, char* argv[])
//{
//	SENSE4_CONTEXT *ps4ctx = NULL;
//	DWORD dwSize = 0;
//	DWORD dwBytesReturned = 0;
//	WORD wModID = 0;
//	WORD wNewtimeouts = 0;
//	BYTE bIn[8] = { 0 };
//	BYTE bOut[8] = { 0 };
//
//
//	unsigned char lpUserPin[8] = "12345678";
//	
//	/*unsigned char lpPlainText[] = "The data to be encrypted inside the SenseLock EL device.";*/
//	unsigned char lpPlainText[] = "orhan topdag The data to be encrypted inside the SenseLock EL device.";
//
//    unsigned long dwPlainTextLen = sizeof(lpPlainText);
//	unsigned char lpCipherText[RSA_BLOCK_LEN];
//    unsigned long dwCipherTextLen = RSA_BLOCK_LEN;
//	
//	unsigned char lpDigest[SHA1_BLOCK_LEN];
//	unsigned long dwDigestLen = 0;
//
//	unsigned char lpToBeSigned[] = "The data to be signed inside the SenseLock EL device.";
//	unsigned char lpSignature[RSA_BLOCK_LEN];
//	unsigned long dwSignatureLen = RSA_BLOCK_LEN;

//   /* if (!(dwResult = OpenS4ByIndex(FIRST_S4_INDEX,&stS4Ctx)))
//	{
//		return 1;
//	} 
//	
//	dwResult = S4ChangeDir(&stS4Ctx, "\\");
//	if (dwResult != S4_SUCCESS) 
//	{
//		printf("Change directory failed! <error code: 0x%08x>\n",dwResult);
//		S4Close(&stS4Ctx);
//		return dwResult;
//	}*/
//	
//	// Call S4VerifyPin(...) to verify User PIN so as to get the privilege to execute the program in SenseLock EL.
//	/*dwResult = S4VerifyPin(&stS4Ctx, lpUserPin, sizeof(lpUserPin), S4_USER_PIN);
//	if (dwResult != S4_SUCCESS) 
//	{
//		printf("Verify Pin failed! <error code: 0x%08x>\n",dwResult);
//		S4Close(&stS4Ctx);
//		return dwResult;
//	}*/
//	DWORD dwResult = S4Enum(NULL, &dwSize);
//	if (dwResult != S4_SUCCESS && dwResult != S4_INSUFFICIENT_BUFFER)
//	{
//		printf("Enumerate EliteIV failed! <error code: 0x%08x>\n", dwResult);
//		getch();
//		return 0;
//	}
//	if (0 == dwSize)
//	{
//		printf("No EliteIV device present!\n");
//		getch();
//		return 1;
//	}
//
//	// 分配内存
//	ps4ctx = (PSENSE4_CONTEXT)malloc(dwSize);
//	if (NULL == ps4ctx)
//	{
//		printf("malloc failed! \n");
//		getch();
//		return 1;
//	}
//	ks4ctx = ps4ctx;
//	// 保存网络锁结构体信息
//	dwResult = S4Enum(ps4ctx, &dwSize);
//	if (S4_SUCCESS != dwResult)
//	{
//		printf("S4Enum failed with error.\n");
//		free(ps4ctx);
//		ps4ctx = NULL;
//		getch();
//		return 1;
//	}
//	printf("S4Enum success.\n");
//
//	// 打开网络锁
//	dwResult = S4Open(ps4ctx);
//	if (S4_SUCCESS != dwResult)
//	{
//		printf("S4Open for device failed with error.\n");
//		free(ps4ctx);
//		ps4ctx = NULL;
//		getch();
//		return 1;
//	}
//	printf("S4Open success.\n");
//
//	// 获取授权
//	wModID = 0;
//	dwResult = S4Control(ps4ctx, S4_GET_LICENSE, &wModID, 2, NULL, 0, &dwBytesReturned);
//	if (S4_SUCCESS != dwResult)
//	{
//		printf("S4_GET_LICENSE module 1 in the device failed.\n");
//		S4Close(ps4ctx);
//
//		free(ps4ctx);
//		ps4ctx = NULL;
//		getch();
//		return 1;
//	}
//	printf("S4_GET_LICENSE success.\n");
//	//
//
//
//
//
//	//
//	memset(bOut, 0, 8);
//	memcpy(bIn, "1234abcd", 8);
//	dwResult = S4Execute(ps4ctx, "d001", bIn, sizeof(bIn), bOut, 8, &dwBytesReturned);
//	if (S4_SUCCESS != dwResult)
//	{
//		printf("S4Execute failed.\n");
//		S4Close(ps4ctx);
//		free(ps4ctx);
//		ps4ctx = NULL;
//		getch();
//		return 1;
//	}
//	if (memcmp(bOut, "dcba4321", 8) != 0)
//	{
//		printf("S4Execute result error.\n");
//		S4Close(ps4ctx);
//		free(ps4ctx);
//		ps4ctx = NULL;
//		getchar();
//		return 1;
//	}
//	printf("S4Execute success.\n");
//	printf("Begin digest...\n");
//	dwResult = Digest(DA_MD5,lpToBeSigned,sizeof(lpToBeSigned),lpDigest,&dwDigestLen);
//	if (dwResult) 
//	{
//		printf("Digest failed with error code:0x%x\n",dwResult);
//		ResetAndCloseS4(ps4ctx);
//		return dwResult;
//	}
//	printf("Success! The digest:");
//	hexprint(stdout,lpDigest,dwDigestLen);
//
//	printf("\nBegin make_signature...\n");
//	if (!(dwResult = make_signature(0xef02,DA_MD5,lpDigest,dwDigestLen,lpSignature,&dwSignatureLen, ps4ctx, dwBytesReturned)))
//	{
//		ResetAndCloseS4(ps4ctx);
//		return dwResult;
//	}
//	printf("Success! The signature:");
//	hexprint(stdout,lpSignature,dwSignatureLen);
//
//    printf("\nBegin verify_signature...\n");
//	if (!(dwResult = verify_signature(0xef01,DA_MD5,lpDigest,dwDigestLen,lpSignature,dwSignatureLen, ps4ctx, dwBytesReturned)))
//	{
//		ResetAndCloseS4(ps4ctx);
//		return dwResult;
//	}
//	printf("Success:correct signature!\n");
//	
//	printf("\nBegin Encryption...\n");
//	if (!(dwResult = rsa_encrypt(0xef01,lpPlainText,sizeof(lpPlainText),lpCipherText,&dwCipherTextLen, ps4ctx, dwBytesReturned)))
//	{
//		ResetAndCloseS4(ps4ctx);
//		return dwResult;
//	}
//
//	printf("Success! The ciphertext:");
//	hexprint(stdout, lpCipherText,dwCipherTextLen);
//	
//	printf("\nBegin Decryption...\n");
//    if (!(dwResult = rsa_decrypt(0xef02,lpCipherText,dwCipherTextLen,lpPlainText,&dwPlainTextLen, ps4ctx, dwBytesReturned)))
//	{
//		ResetAndCloseS4(ps4ctx);
//		return dwResult;
//	}
//	printf("Success! The plaintext:\n%s\n",lpPlainText);
//	
//	/* for better security,use the following instead of using S4close() directly */
//	ResetAndCloseS4(ps4ctx);
//
//	getch();
//	return dwResult;
//}


/*__declspec(dllexport) */int main(int argc, char* argv[])
{
	SENSE4_CONTEXT *ps4ctx = NULL;
	DWORD dwSize = 0;
	DWORD dwBytesReturned = 0;
	WORD wModID = 0;
	WORD wNewtimeouts = 0;
	BYTE bIn[8] = { 0 };
	BYTE bOut[8] = { 0 };


	unsigned char lpUserPin[8] = "12345678";
	
	/*unsigned char lpPlainText[] = "The data to be encrypted inside the SenseLock EL device.";*/
	unsigned char lpPlainText[] = "orhan topdag The data to be encrypted inside the SenseLock EL device.";

    unsigned long dwPlainTextLen = sizeof(lpPlainText);
	unsigned char lpCipherText[RSA_BLOCK_LEN];
    unsigned long dwCipherTextLen = RSA_BLOCK_LEN;
	
	unsigned char lpDigest[SHA1_BLOCK_LEN];
	unsigned long dwDigestLen = 0;

	unsigned char lpToBeSigned[] = "The data to be signed inside the SenseLock EL device.";
	unsigned char lpSignature[RSA_BLOCK_LEN];
	unsigned long dwSignatureLen = RSA_BLOCK_LEN;

   /* if (!(dwResult = OpenS4ByIndex(FIRST_S4_INDEX,&stS4Ctx)))
	{
		return 1;
	} 
	
	dwResult = S4ChangeDir(&stS4Ctx, "\\");
	if (dwResult != S4_SUCCESS) 
	{
		printf("Change directory failed! <error code: 0x%08x>\n",dwResult);
		S4Close(&stS4Ctx);
		return dwResult;
	}*/
	
	// Call S4VerifyPin(...) to verify User PIN so as to get the privilege to execute the program in SenseLock EL.
	/*dwResult = S4VerifyPin(&stS4Ctx, lpUserPin, sizeof(lpUserPin), S4_USER_PIN);
	if (dwResult != S4_SUCCESS) 
	{
		printf("Verify Pin failed! <error code: 0x%08x>\n",dwResult);
		S4Close(&stS4Ctx);
		return dwResult;
	}*/
	DWORD dwResult = S4Enum(NULL, &dwSize);
	if (dwResult != S4_SUCCESS && dwResult != S4_INSUFFICIENT_BUFFER)
	{
		printf("Enumerate EliteIV failed! <error code: 0x%08x>\n", dwResult);
		/*getch();*/
		return dwResult;
	}
	if (0 == dwSize)
	{
		printf("No EliteIV device present!\n");
		getch();
		return dwResult;
	}

	// 分配内存
	ps4ctx = (PSENSE4_CONTEXT)malloc(dwSize);
	if (NULL == ps4ctx)
	{
		printf("malloc failed! \n");
		/*getch();*/
		return dwResult;
	}

	// 保存网络锁结构体信息
	dwResult = S4Enum(ps4ctx, &dwSize);
	if (S4_SUCCESS != dwResult)
	{
		printf("S4Enum failed with error.\n");
		free(ps4ctx);
		ps4ctx = NULL;
	
		return dwResult;
	}
	printf("S4Enum success.\n");

	// 打开网络锁
	dwResult = S4Open(ps4ctx);
	if (S4_SUCCESS != dwResult)
	{
		printf("S4Open for device failed with error.\n");
		free(ps4ctx);
		ps4ctx = NULL;
	
		return dwResult;
	}
	printf("S4Open success.\n");

	// 获取授权
	wModID = 0;
	dwResult = S4Control(ps4ctx, S4_GET_LICENSE, &wModID, 2, NULL, 0, &dwBytesReturned);
	if (S4_SUCCESS != dwResult)
	{
		printf("S4_GET_LICENSE module 1 in the device failed.\n");
		S4Close(ps4ctx);

		free(ps4ctx);
		ps4ctx = NULL;

		return dwResult;
	}
	printf("S4_GET_LICENSE success.\n");
	//




	//
	memset(bOut, 0, 8);
	memcpy(bIn, "1234abcd", 8);
	dwResult = S4Execute(ps4ctx, "d001", bIn, sizeof(bIn), bOut, 8, &dwBytesReturned);
	if (S4_SUCCESS != dwResult)
	{
		printf("S4Execute failed.\n");
		S4Close(ps4ctx);
		free(ps4ctx);
		ps4ctx = NULL;
		
		return dwResult;
	}
	ks4ctx = ps4ctx;
	if (memcmp(bOut, "dcba4321", 8) != 0)
	{
		printf("S4Execute result error.\n");
		S4Close(ps4ctx);
		free(ps4ctx);
		ps4ctx = NULL;
	
		return dwResult;
	}
	printf("S4Execute success.\n");
	printf("Begin digest...\n");
	dwResult = Digest(DA_MD5,lpToBeSigned,sizeof(lpToBeSigned),lpDigest,&dwDigestLen);
	if (dwResult) 
	{
		printf("Digest failed with error code:0x%x\n",dwResult);
		ResetAndCloseS4(ps4ctx);
		return dwResult;
	}
	printf("Success! The digest:");
	hexprint(stdout,lpDigest,dwDigestLen);

	printf("\nBegin make_signature...\n");
	if (!(dwResult = make_signature(0xef02,DA_MD5,lpDigest,dwDigestLen,lpSignature,&dwSignatureLen, ps4ctx, dwBytesReturned)))
	{
		ResetAndCloseS4(ps4ctx);
		return dwResult;
	}
	printf("Success! The signature:");
	hexprint(stdout,lpSignature,dwSignatureLen);

    printf("\nBegin verify_signature...\n");
	if (!(dwResult = verify_signature(0xef01,DA_MD5,lpDigest,dwDigestLen,lpSignature,dwSignatureLen, ps4ctx, dwBytesReturned)))
	{
		ResetAndCloseS4(ps4ctx);
		return dwResult;
	}
	printf("Success:correct signature!\n");
	
	printf("\nBegin Encryption...\n");
	if (!(dwResult = rsa_encrypt(0xef01,lpPlainText,sizeof(lpPlainText),lpCipherText,&dwCipherTextLen, ps4ctx, dwBytesReturned)))
	{
		ResetAndCloseS4(ps4ctx);
		return dwResult;
	}
	printf("Success! The ciphertext:");
	hexprint(stdout, lpCipherText,dwCipherTextLen);
	
	printf("\nBegin Decryption...\n");
    if (!(dwResult = rsa_decrypt(0xef02,lpCipherText,dwCipherTextLen,lpPlainText,&dwPlainTextLen, ps4ctx, dwBytesReturned)))
	{
		ResetAndCloseS4(ps4ctx);
		return dwResult;
	}
	printf("Success! The plaintext:\n%s\n",lpPlainText);
	return 315;
	/* for better security,use the following instead of using S4close() directly */
	/*ResetAndCloseS4(ps4ctx);*/

	/*getch();
	return dwResult;*/
}
__declspec(dllexport) void printMessage() {

	printf("Hello world");
}
__declspec(dllexport) int close() {

	ResetAndCloseS4(ks4ctx);
	printf("Hello world");
	return 1;
}
















