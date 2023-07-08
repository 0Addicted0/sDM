#ifndef _CME_HH_
#define _CME_HH_

#include "../sDMdef.hh"
#include "../alg_src/sm4/SM4_ENC.hh"
#include "../alg_src/sm3/SM3.hh"

namespace gem5
{
    namespace CME
    {
        extern int FAST_MODE;
        void CMEdump(char *title, uint8_t *tptr, size_t sz);
        void dump(char *title, uint8_t *txt, int len);
        void ConstructOTP(sDM::Addr paddr2CL, uint8_t *counter, int counterLen, uint8_t *OTP);
        void sDM_Encrypt(uint8_t *plaint, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL);
        void sDM_Decrypt(uint8_t *cipher, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL);
        void sDM_HMAC(uint8_t *input, int inputLen, uint8_t *hamc_key, sDM::Addr paddr, uint8_t *counter, int counterLen, uint8_t *hmac, int hmacLen);
    }
}
#endif // _CME_HH_
