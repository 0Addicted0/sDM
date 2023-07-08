// #include "../IIT/IIT.hh"
#include "../IIT/IIT.hh"

using namespace std;
#define SM4_SIZE 16

int main()
{
    // 测试加密函数正确性
    // gem5::sm4::SM4_SelfCheck();
    uint8_t plaint[CL_SIZE] = {0x00};
    for (int i = 0; i < 16; i++)
        plaint[i] = i;
    // gem5::CME::dump("plaint",plaint, CL_SIZE);
    // uint8_t cipher[SM4_SIZE] = {0x00};
    gem5::sDM::CL_Counter cl;
    uint8_t ckey[SM4_KEY_SIZE] = {0};
    memset(ckey, 0, sizeof(ckey));
    memset(cl, 0, sizeof(cl));
    gem5::CME::sDM_Encrypt(plaint, cl, sizeof(cl), 0x0, ckey);
    gem5::CME::dump("enc", plaint, CL_SIZE);
    gem5::CME::sDM_Decrypt(plaint, cl, sizeof(cl), 0x0, ckey);
    gem5::CME::dump("dec", plaint, CL_SIZE);
    return 0;
}