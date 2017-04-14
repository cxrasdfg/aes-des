/**
 * created by theppsh on 17-4-11
 * */

#include <iostream>
#include <chrono>
#include <iomanip>
#include "src/des.hpp"
#include "src/triple_des.hpp"
int main() {

    auto _cout_defualt_flag = std::cout.flags();  //cout的输出格式貌似是状态机啊- -

    /** des ecb 加密测试*/
    des::ElemType  plain_block[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};  // 明文
    des::ElemType  cipher_block[] = {0,0,0,0,0,0,0,0};  // 存放密文的空间
    des::ElemType  key_block[] = {0,0,0,0,0,0,0,0};  // 秘钥

    des::ElemType  bit_key[64];  // 用于存储秘钥的比特位的空间,每一个比特位用一个字节表示
    des::ElemType  sub_keys[16][48]; // 存放16个子钥的空间，每一个子钥是48比特

    /** 112b全0密钥加密数据FF FF FF FF FF FF FF FF */

    /** 这里的三重des key1 key3本来就是相等的，然后需要112b的全0秘钥 故key2也与key1 key3 相等，均为0*/
    std::cout<<"******* 112b全0密钥加密数据FF FF FF FF FF FF FF FF ******** "<<std::endl;
    _3_des::_3_DES_EncryptBlock(plain_block,key_block,key_block,key_block,cipher_block);
    for(int i=0;i<8;i++){
        std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<std::internal<<int(cipher_block[i])<<" ";
    }

    std::cout<<std::endl;
    std::cout<<"******* 112b全0密钥加密数据FF FF FF FF FF FF FF FF 后的解密数据 ********"<<std::endl;
    std::memcpy(plain_block,cipher_block,8);
    _3_des::_3_DES_DecryptBlock(cipher_block,key_block,key_block,key_block,plain_block);
    for(int i=0;i<8;i++){
        std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<std::internal<<int(plain_block[i])<<" ";
    }

    std::cout<<std::endl<<std::endl;
    std::cout.setf(_cout_defualt_flag);
    /** 3des ecb加密时间测试*/
    int des_enc_time =100000;  //加密次数

    std::cout<<"********** _3des ecb加密测试 次数:"<<des_enc_time<<" **********"<<std::endl;
    auto  t1=std::chrono::system_clock::now();
    for (int _index =0;_index<des_enc_time;_index++) {
        _3_des::_3_DES_EncryptBlock(plain_block,key_block,key_block,key_block,cipher_block);
    }

    auto  t2= std::chrono::system_clock::now();

    float total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count()/1000.0f/1000.0f;
    std::cout<<des_enc_time<<"次_3des ecb加密总耗时间:"<< total_time<<" ms"<<std::endl;
    std::cout<<des_enc_time<<"次_3des ecb加密平均消耗时间:" << total_time/des_enc_time<<" ms"<<std::endl;

    /** CBC加密方式 */

    //64 bytes的cbc明文
    des::ElemType des_cbc_plain_blocks[][8] = {
            {0xff,0xff,0xff,0x12,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0x97,0xff,0xff,0xff,0xff,0xff,0xff},
            {0xff,0xff,0xff,0xff,0xff,0xff,0x98,0xff},
    };

    des::ElemType des_cbc_cipher_blocks[8][8];  // des cbc模式加密后的密文存放空间
    des::ElemType des_cbc_key_block[] = {0,0,0,0,0,0,0,0};
    des::ElemType des_cbc_bit_key_block[64];   //用一个字节代表一位
    des::ElemType des_cbc_sub_keys[16][48];  //存放子钥的空间
    des::ElemType  des_cbc_init_vector[] ={0x11,0,0,0,0,0,0,0};  //初始向量 64bit
    des::ElemType des_cbc_xor_result [8];  // 用于存储异或操作后的结果

    std::cout<<std::endl;
    std::cout<<"********** des cbc加密测试: **********"<<std::endl;
    des::Char8ToBit64(des_cbc_key_block,des_cbc_bit_key_block);
    des::DES_MakeSubKeys(des_cbc_bit_key_block,des_cbc_sub_keys);
    for(int i=0;i<8;i++){
        // 先进行异或操作
        if(i==0)
            des::DES_CBC_XOR(des_cbc_init_vector,des_cbc_plain_blocks[i],des_cbc_xor_result);
        else
            des::DES_CBC_XOR(des_cbc_cipher_blocks[i-1],des_cbc_plain_blocks[i],des_cbc_xor_result);
        des::DES_EncryptBlock(des_cbc_xor_result,des_cbc_sub_keys,des_cbc_cipher_blocks[i]);
    }

    for(int i=0;i<8;i++){
        for(int j=0;j<8;j++){
            std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<std::internal<<int(des_cbc_cipher_blocks[i][j])<<" ";
        }
        std::cout<<std::endl;

    }
    std::cout<<std::endl;
    std::cout.setf(_cout_defualt_flag);  //恢复默认cout的输出格式

    std::cout<<"********** des cbc 解密测试: **********"<<std::endl;

    for (int i=0; i<8;i++){
        des::DES_DecryptBlock(des_cbc_cipher_blocks[i],des_cbc_sub_keys,des_cbc_xor_result);
        if (i==0)
            des::DES_CBC_XOR(des_cbc_init_vector,des_cbc_xor_result,des_cbc_plain_blocks[i]);
        else
            des::DES_CBC_XOR(des_cbc_cipher_blocks[i-1],des_cbc_xor_result,des_cbc_plain_blocks[i]);
    }

    for(int i=0;i<8;i++){
        for(int j=0;j<8;j++){
            std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<int(des_cbc_plain_blocks[i][j])<<" ";
        }
        std::cout<<std::endl;
    }

    std::cout.setf(_cout_defualt_flag);  // 回复默认cout的输出格式

    return 0;
}