#include "CME.hh"
#include "cassert"

#include <string.h>
#include <stdint.h>
#define SM3_PADLEN (SM3_len >> 3) // = SM3_SIZE
#define GETOPAD(x, y)                    \
    for (int i = 0; i < SM3_PADLEN; i++) \
        (x)[i] = (y)[i] ^ 0x5c;
#define GETIPAD(x, y)                    \
    for (int i = 0; i < SM3_PADLEN; i++) \
        (x)[i] = (y)[i] ^ 0x36;
namespace gem5
{
    namespace CME
    {
        /**
         * CME
         * |  -----------------------------------\
         * |                 OTP                  |
         * |---8B---|---10B---|---16B---|---16B---|
         * |--pADDR-|-counter-|----2----|----3----|
         * 0        15       31        47        63
         *                   SM4
         * |-----------------XOR-------------------|
         * |----------------plaint-----------------|
         * |                  ||                   |
         * |----------------cipher-----------------|
         */
        const uint8_t MAGIC1 = 0x5A;
        const uint8_t MAGIC2 = 0xA5;
        const uint8_t MAGIC3 = 0x3C;
        const uint8_t MAGIC4 = 0xC3;
        const uint32_t counterLen = 10;
        /**
         * @author yqy
         * @brief 构造OTP(512bit)
         * @param paddr2CL 明文数据指针
         * @param counter 计数器指针
         * @param counterLen 字节长度:CL_Counter 10B
         * @param OTP 存放OTP的指针
         */
        void ConstructOTP(sDM::Addr paddr2CL, uint8_t *counter, int counterLen, uint8_t *OTP)
        {
            memset(OTP, 0, CL_SIZE);
            for (int i = 0; i < counterLen; i++)
                *(OTP + 0 + i) = *counter;         // 0~9B  :counter
            *((sDM::Addr *)(OTP + 10)) = paddr2CL; // 10~17B:addr
                                                   // 18~19B:0x0
            for (int i = 0; i < counterLen; i++)
                *(OTP + 20 + i) = *counter;        // 20~29B:counter
            *((sDM::Addr *)(OTP + 30)) = paddr2CL; // 30~37B:addr
                                                   // 38~39B:0x0
            for (int i = 0; i < counterLen; i++)
                *(OTP + 40 + i) = *counter;        // 40~49B:counter
            *((sDM::Addr *)(OTP + 50)) = paddr2CL; // 50-47B:addr
                                                   // 58~59B:0x0

            *((uint8_t *)(OTP + 60)) = MAGIC1; // 60B:MAGIC1
            *((uint8_t *)(OTP + 61)) = MAGIC2; // 61B:MAGIC2
            *((uint8_t *)(OTP + 62)) = MAGIC3; // 62B:MAGIC3
            *((uint8_t *)(OTP + 63)) = MAGIC4; // 63B:MAGIC4
        }
        /**
         * @brief :
         * 使用counter mode加密plaint(64B)
         * @author yqy
         * @param plaint CL数据指针
         * @param counter CL counter指针
         * @param counterLen 计数器字节长度10B(sizeof(CL_Counter))
         * @param paddr2CL CL的物理地址
         * @param key2EncryptionCL 加密密钥指针
         */
        void sDM_Encrypt(uint8_t *plaint, uint8_t *counter, int counterLen, sDM::Addr addr2CL, uint8_t *key2EncryptionCL)
        {
            // 加密分块数
            uint8_t OTP[CL_SIZE], otp_cipher[SM4_INPUT_SIZE];
            ConstructOTP(addr2CL, counter, counterLen, OTP);
            memset(otp_cipher, 0, SM4_INPUT_SIZE);
            int rdcnt = CL_SIZE / SM4_INPUT_SIZE;
            for (int i = 0; i < rdcnt; i++)
            {
                sm4::SM4_Encrypt(key2EncryptionCL, OTP + (i << 4), otp_cipher);
                for (int j = 0; j < SM4_INPUT_SIZE; j++)
                    (*(plaint + (i << 4) + j)) ^= otp_cipher[j];
            }
        }
        /**
         * @brief 使用counter mode解密cipher
         * @author yqy
         * @param cipher 数据指针
         * @param counter CL_Counter指针
         * @param counterLen 计数器字节长度10B(sizeof(CL_Counter))
         * @param paddr2CL CL物理地址
         * @param key2EncryptionCL 密钥指针
         */
        void sDM_Decrypt(uint8_t *cipher, uint8_t *counter, int counterLen, sDM::Addr paddr2CL, uint8_t *key2EncryptionCL)
        {
            // 加密分块数
            uint8_t OTP[CL_SIZE], otp_plaint[SM4_INPUT_SIZE];
            ConstructOTP(paddr2CL, counter, counterLen, OTP);

            memset(otp_plaint, 0, SM4_INPUT_SIZE);
            int rdcnt = CL_SIZE / SM4_INPUT_SIZE;
            for (int i = 0; i < rdcnt; i++)
            {
                sm4::SM4_Decrypt(key2EncryptionCL, OTP + (i << 4), otp_plaint);
                for (int j = 0; j < SM4_INPUT_SIZE; j++)
                    (*(cipher + (i << 4) + j)) ^= otp_plaint[j];
            }
        }
        /**
         * @author
         * yqy
         * @brief
         * 计算密文数据(半页)的HMAC
         * @param input    输入消息指针
         * @param inputLen 输入消息字节长度
         * @param hamc_key 用于计算hmac的密钥
         * @param paddr    输入消息的物理地址
         * @param counter  512bit(含有部分填充0)的节点指针
         * @param counterLen 计数器字节长度
         * @param hmac     计算结果存储指针
         * @param hmacLen  输出字节长度
         * @attention
         * 这个函数用于计算iit节点的hash_tag(传入的counter是全零)和hamc
         */
        void sDM_HMAC(uint8_t *input, int inputLen, uint8_t *hamc_key, sDM::Addr paddr, uint8_t *counter, int counterLen, uint8_t *hmac, int hmacLen)
        {
            assert(hmacLen <= SM3_SIZE && "invalid output length");
            int Mlen = (inputLen + counterLen + sizeof(sDM::Addr));
            int PaddingLen = (SM3_SIZE - (Mlen % SM3_SIZE)) % SM3_SIZE;
            uint8_t V[SM3_PADLEN + Mlen + PaddingLen], p1[SM3_SIZE];
            GETIPAD(V, hamc_key);
            // (ipad ^ K)||(M[input||counter||addr]|padding|)
            memcpy(V + SM3_PADLEN, input, inputLen);
            memcpy(V + SM3_PADLEN + inputLen, counter, counterLen);
            memcpy(V + SM3_PADLEN + inputLen + counterLen, &paddr, sizeof(sDM::Addr));
            // H((ipad ^ K)||M)
            sm3::SM3_256(V, SM3_PADLEN + Mlen + PaddingLen, p1); // P1= H((ipad ^ K)||M)
            // (opad ^ K) || H((ipad ^ K)||M)
            GETOPAD(V, hamc_key);
            memcpy(V + SM3_SIZE, p1, SM3_SIZE);
            // H((opad ^ K) || H((ipad ^ K)||M)
            sm3::SM3_256(V, SM3_SIZE + SM3_SIZE, p1);
            // cut
            memcpy(hmac, p1, hmacLen);
        }
    }
}
