/**
 * created by theppsh on 17-4-11
 * */

#include <iostream>
#include <chrono>
#include <iomanip>
#include "src/des.hpp"
#include "src/triple_des.hpp"
int main() {

    /** des ecb 加密测试*/
    des::ElemType  plain_block[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};  // 明文
    des::ElemType  cipher_block[] = {0,0,0,0,0,0,0,0};  // 存放密文的空间
    des::ElemType  key_block[] = {0,0,0,0,0,0,0,0};  // 秘钥

    des::ElemType  bit_key[64];  // 用于存储秘钥的比特位的空间,每一个比特位用一个字节表示
    des::ElemType  sub_keys[16][48]; // 存放16个子钥的空间，每一个子钥是48比特


    /** des ecb加密时间测试*/
    int des_enc_time =100000;  //加密次数

    std::cout<<"********** des ecb加密测试 次数:"<<des_enc_time<<" **********"<<std::endl;
    auto  t1=std::chrono::system_clock::now();
    for (int _index =0;_index<des_enc_time;_index++) {

        des::Char8ToBit64(key_block,bit_key);  //将秘钥转换成比特位，
        des::DES_MakeSubKeys(bit_key,sub_keys);  //利用比特位表示的64位秘钥生成子钥

        des::DES_EncryptBlock(plain_block,sub_keys,cipher_block);

        for (int i = 0; i < 8; i++) {
            //std::printf("%02x ",cipher_block[i]);
        }
        //std::printf("\n");
    }

    auto  t2= std::chrono::system_clock::now();

    float total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count()/1000.0f/1000.0f;
    std::cout<<des_enc_time<<"次des ecb加密总耗时间:"<< total_time<<" ms"<<std::endl;
    std::cout<<des_enc_time<<"次des ecb加密平均消耗时间:" << total_time/des_enc_time<<" ms"<<std::endl;

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
    des::ElemType  des_cbc_init_vector[] ={0,0,0,0,0,0,0,0};  //初始向量 64bit
    des::ElemType des_cbc_xor_result [8];  // 用于存储异或操作后的结果

    std::cout<<std::endl;
    std::cout<<"********** des cbc加密测试: **********"<<std::endl;
    auto _cout_defualt_flag = std::cout.flags();  //cout的输出格式貌似是状态机啊- -
    des::Char8ToBit64(des_cbc_key_block,des_cbc_bit_key_block);
    des::DES_MakeSubKeys(des_cbc_bit_key_block,des_cbc_sub_keys);
    for(int i=0;i<8;i++){
        // 先进行异或操作
        if(i==0)
            des::DES_CBC_XOR(des_cbc_init_vector,des_cbc_plain_blocks[i],des_cbc_xor_result);
        else
            des::DES_CBC_XOR(des_cbc_cipher_blocks[i-1],des_cbc_plain_blocks[i],des_cbc_xor_result);
        des::DES_EncryptBlock(des_cbc_xor_result,sub_keys,des_cbc_cipher_blocks[i]);
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


    /**3重des 加密测试*/

    std::cout<<std::endl;
    std::cout<<"********** triple des 加密测试 **********"<<std::endl;
    des::ElemType _3_des_cipher_block[8];
    des::ElemType _3_des_plain_block[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    des::ElemType _3_des_key1[]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};  //key1
    des::ElemType _3_des_key2[]={0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02};  //key2
    des::ElemType _3_des_key3[]={0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03};

    _3_des::_3_DES_EncryptBlock(_3_des_plain_block,_3_des_key1,_3_des_key2,_3_des_key3,_3_des_cipher_block);

    for(int i=0;i<8;i++){
        std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<std::internal<<int(_3_des_cipher_block[i])<<" ";
    }

    std::cout<<std::endl;
    std::cout.setf(_cout_defualt_flag);

    /**3重des 解密测试*/

    std::cout<<std::endl;
    std::cout<<"********** tripe des 解密测试 **********"<<std::endl;

    std::memset(_3_des_plain_block,0,sizeof(_3_des_plain_block));
    _3_des::_3_DES_DecryptBlock(_3_des_cipher_block,_3_des_key1,_3_des_key2,_3_des_key3,_3_des_plain_block);
    for(int i=0;i<8;i++){
        std::cout<<std::hex<<std::showbase<<std::setw(4)<<std::setfill('0')<<std::internal<<int(_3_des_plain_block[i])<<" ";
    }
    std::cout<<std::endl;

    return 0;
}