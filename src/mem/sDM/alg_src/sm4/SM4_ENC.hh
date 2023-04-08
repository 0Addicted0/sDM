//Function List:
//SM4_KeySchedule//Generate the required round keys
//SM4_Encrypt    //Encryption function
//SM4_Decrypt    //Decryption function
//SM4_SelfCheck  //Self-check
#ifndef __SM4_H
#define __SM4_H
#include <stdio.h>
//rotate n bits to the left in a 32bit buffer
#define SM4_Rotl32(buf, n) (((buf)<<n)|((buf)>>(32-n)))
#define SM4_INPUT_SIZE 16 // SM4 加密字节粒度
#define SM4_KEY_SIZE 16 // SM4 密钥字节长度
namespace gem5
{
    namespace sm4
    {
        extern unsigned int SM4_CK[32];
        extern unsigned char SM4_Sbox[256];
        extern unsigned int SM4_FK[4];
        extern unsigned char SM4_n[16];
        /************************************************************
        Function:
        void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]);
        Description:
        Generate round keys
        Calls:
        Called By:
        SM4_Encrypt;
        SM4_Decrypt;
        @param
        MK[]: Master key
        Output:
        rk[]: round keys
        @return  null
        Others:
        ************************************************************/
        void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]);
        /************************************************************
        Function:
        void SM4_Encrypt(unsigned char MK[],unsigned char PlainText[],unsigned char
        CipherText[]);
         Description:
        Encryption function
        Calls:
        SM4_KeySchedule
        Called By:
        @param
        MK[]: Master key
        PlainText[]: input text
        @result
        CipherText[]: output text
        @return null
        Others:
        ************************************************************/
        void SM4_Encrypt(unsigned char MK[],unsigned char PlainText[],unsigned char CipherText[]);
        /************************************************************
        Function:
        void SM4_Decrypt(unsigned char MK[],unsigned char CipherText[], unsigned char PlainText[]);
        Description:
        Decryption function
        Calls:
        SM4_KeySchedule
        Called By:
        @param
        MK[]: Master key
        CipherText[]: input text
        @result
        PlainText[]: output text
        Return:null
        Others:
        ************************************************************/
        void SM4_Decrypt(unsigned char MK[],unsigned char CipherText[], unsigned char PlainText[]);
        /************************************************************
        Function:
        int SM4_SelfCheck()
        Description:
        Self-check with standard data
        Calls:
        SM4_Encrypt;
        SM4_Decrypt;
        Called By:
        Input:
        Output:
        Return:
        1 fail ; 0 success
        Others:
        ************************************************************/
        int SM4_SelfCheck();
    }
}
#endif
