//
// Created by theppsh on 17-4-13.
//

#include <iostream>
#include <iomanip>
#include "src/aes.hpp"
#include "src/des.hpp"
int main(int argc,char ** args){

    /**aes 加密*/

    /// 128位全0的秘钥
    u_char key_block[]={0,0,0,0,0,0,0,0,
                        0,0,0,0,0,0,0,0
    };
    u_char  plain_block[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                           0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    };

    u_char  cipher_block[16];
    AES aes_test(key_block);


    std::cout<<"********** aes 加密测试 **********"<<std::endl;
    std::memcpy(cipher_block,plain_block,16);
    aes_test.Cipher(cipher_block);

    auto cout_default_flags = std::cout.flags();
    for(int i=0;i<16;i++){
        std::cout<<std::hex<<std::internal<<std::showbase<<std::setw(4)<<std::setfill('0')<<int(cipher_block[i])<<" ";
    }
    std::cout.setf(cout_default_flags);
    std::cout<<std::endl;
    std::cout<<std::endl;
    std::cout<<"********** aes 解密测试 **********"<<std::endl;
    std::memcpy(plain_block,cipher_block,16);
    aes_test.InvCipher(plain_block);


    for(int i=0;i<16;i++){
        std::cout<<std::hex<<std::internal<<std::showbase<<std::setw(4)<<std::setfill('0')<<int(plain_block[i])<<" ";
    }
    std::cout<<std::endl;
    std::cout.setf(cout_default_flags);

    /// ***aes加密文件测试 ***

    std::cout<<std::endl;
    std::cout<<"******** aes 加密文件测试 ********"<<std::endl;

    std::string plain_txt= "/media/C/课程与作业/网络安全/实验课/实验一/aes_and_des/resoureces/plain.txt";
    std::string cipher_txt = "/media/C/课程与作业/网络安全/实验课/实验一/aes_and_des/resoureces/cipher.txt";
    std::string decipher_txt = "/media/C/课程与作业/网络安全/实验课/实验一/aes_and_des/resoureces/decipher.txt";

    aes_test.CipherFile(plain_txt,cipher_txt);

    std::cout<<std::endl;

    std::cout<<"******** 解密文件测试 ********"<<std::endl;
    aes_test.InvCipherFile(cipher_txt,decipher_txt);

   [](const std::string & file_path1,const std::string file_path2){
        std::fstream f1,f2;
        f1.open(file_path1);
        f2.open(file_path2);

        assert(f1.is_open());
        assert(f2.is_open());

        f1.seekg(0,std::ios::end);
        f2.seekg(0,std::ios::end);
        int f1_size = static_cast<int>(f1.tellg());
        int f2_size = static_cast<int>(f2.tellg());

        std::shared_ptr<char> f1_file_buffer(new char[f1_size+1]);
        std::shared_ptr<char> f2_file_buffer(new char[f2_size+1]);

        f1.seekg(0,std::ios::beg);
        f2.seekg(0,std::ios::beg);

        f1.read(f1_file_buffer.get(),f1_size);
        f2.read(f2_file_buffer.get(),f2_size);

        f1_file_buffer.get()[f1_size]='\0';
        f2_file_buffer.get()[f2_size]='\0';

        if(std::strcmp(f1_file_buffer.get(),f2_file_buffer.get())!=0){
            std::cout<<"文件加密解密后的文件与原来的文件不一致"<<std::endl;
            exit(0);
        }else{
            std::cout<<"文件加密解密通过！"<<std::endl;
        }
    }(plain_txt,decipher_txt);

    /// aes 与 des 的加密解密的速度的测试 均加密128位即16个byete的数据
    std::cout<<std::endl;
    std::cout<<"******** ase & des加密解密的速度的测试****** "<< std::endl;

    int enc_times =100000;  //加密而次数s

    // 先测试 des
    {
        u_char des_bit_keys[64];
        u_char des_sub_keys[16][48];

        auto t1= std::chrono::system_clock::now();
        for (int _time =0 ; _time < enc_times; _time++){
            des::Char8ToBit64(key_block,des_bit_keys);
            des::DES_MakeSubKeys(des_bit_keys,des_sub_keys);

            des::DES_EncryptBlock(plain_block,des_sub_keys,cipher_block);
            des::DES_EncryptBlock(plain_block+8,des_sub_keys,cipher_block+8); //des的块是8个字节也就是64位的。。。

            des::DES_DecryptBlock(cipher_block,des_sub_keys,plain_block);
            des::DES_DecryptBlock(cipher_block+8,des_sub_keys,plain_block+8);
        }

        auto t2 = std::chrono::system_clock::now();

        float total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count()/1000.0f/1000.0f;
        std::cout<<"加密解密128位数消息"<<enc_times<<"次, des总共花费了:"<<total_time<<" ms"<<std::endl;
        std::cout<<"加密解密128位数消息"<<enc_times<<"次, des平均花费了:"<<total_time/enc_times<<" ms"<<std::endl;
    }

    // 再测试aes
    {
        auto t1 =std::chrono::system_clock::now();

        for(int _time = 0; _time<enc_times;_time++){
            aes_test.Cipher(plain_block);

            memcpy(cipher_block,plain_block,16);
            aes_test.InvCipher(cipher_block);
            memcpy(plain_block,cipher_block,16);
        }

        auto t2 = std::chrono::system_clock::now();
        float total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1).count()/1000.0f/1000.0f;
        std::cout<<"加密解密128位数消息"<<enc_times<<"次, aes总共花费了:"<<total_time<<" ms"<<std::endl;
        std::cout<<"加密解密128位数消息"<<enc_times<<"次, aes平均花费了:"<<total_time/enc_times<<" ms"<<std::endl;
    }

    return 0;
}