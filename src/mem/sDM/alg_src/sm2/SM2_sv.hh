/************************************************************************
 File name: SM2_sv.h
 Version: SM2_sv_V1.0
 Date: Sep 27,2016
 Description: implementation of SM2 signature algorithm and verification algorithm
 Function List:
 4.Test_Zero //test if the big x equals zero
 5.Test_n //test if the big x equals n
 6.Test_Range //test if the big x belong to the range[1,n-1]
 7.SM2_KeyGenToArray //generate public key
 8.SM2_Sign //SM2 signature algorithm
 9.SM2_Verify //SM2 verification
 10.SM2_SelfCheck() //SM2 slef-check
 11.SM3_256() //this function can be found in SM3.c and SM3.h
Notes:
This SM2 implementation source code can be used for academic, non-profit making or
non-commercial use only.
This SM2 implementation is created on MIRACL. SM2 implementation source code provider does
not provide MIRACL library, MIRACL license or any permission to use MIRACL library. Any commercial
use of MIRACL requires a license which may be obtained from Shamus Software Ltd.
**************************************************************************/
#ifndef __SM2_SV_H
#define __SM2_SV_H
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "SM2_ENC.hh"
#define ERR_GENERATE_R 0x0000000B
#define ERR_GENERATE_S 0x0000000C
#define ERR_OUTRANGE_R 0x0000000D
#define ERR_OUTRANGE_S 0x0000000E
#define ERR_GENERATE_T 0x0000000F
#define ERR_PUBKEY_INIT 0x0000010
#define ERR_DATA_MEMCMP 0x00000011
namespace gem5
{
    namespace sm2
    {
        int Test_Zero(big x);
        int Test_n(big x);
        int Test_Range(big x);
        int SM2_KeyGenToArray(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);
        int SM2_Sign(unsigned char *message, int len, unsigned char ZA[], unsigned char rand[],
                     unsigned char d[], unsigned char R[], unsigned char S[]);

        int SM2_Verify(unsigned char *message, int len, unsigned char ZA[], unsigned char Px[],
                       unsigned char Py[], unsigned char R[], unsigned char S[]);
        int SM2_SelfCheck();
    }
}
#endif //__SM2_sv
