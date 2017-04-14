/**
 * Created by theppsh on 17-4-13.
 */

#pragma once
#include "des.hpp"

/**三重des*/
namespace _3_des{
    using  des::ElemType;

    ElemType bit_k1[64],bit_k2[64],bit_k3[64],sub_keys1[16][48],sub_keys2[16][48],sub_keys3[16][48],temp[8];

    void _3_DES_EncryptBlock(ElemType plain_block[8],ElemType k1[8],ElemType k2[8],ElemType k3[8],ElemType cipher_bock[8]){
        // 将k1,k2,k3转换到用一个字节表示一位的空间里
        des::Char8ToBit64(k1,bit_k1);
        des::Char8ToBit64(k2,bit_k2);
        des::Char8ToBit64(k3,bit_k3);

        // 分别生成k1,k2,k3对应的子钥
        des::DES_MakeSubKeys(bit_k1,sub_keys1);
        des::DES_MakeSubKeys(bit_k2,sub_keys2);
        des::DES_MakeSubKeys(bit_k3,sub_keys3);

        // 第一重
        des::DES_EncryptBlock(plain_block,sub_keys1,cipher_bock);

        // 第二重
        des::DES_DecryptBlock(cipher_bock,sub_keys2,temp);

        // 第三重
        des::DES_EncryptBlock(temp,sub_keys3,cipher_bock);
    }

    void _3_DES_DecryptBlock(ElemType cipher_block[8],ElemType k1[8],ElemType k2[8],ElemType k3[8],ElemType plain_block[8]){
        // 将k1,k2,k3转换到用一个字节表示一位的空间里
        des::Char8ToBit64(k1,bit_k1);
        des::Char8ToBit64(k2,bit_k2);
        des::Char8ToBit64(k3,bit_k3);

        // 分别生成k1,k2,k3对应的子钥
        des::DES_MakeSubKeys(bit_k1,sub_keys1);
        des::DES_MakeSubKeys(bit_k2,sub_keys2);
        des::DES_MakeSubKeys(bit_k3,sub_keys3);

        //第三重
        des::DES_DecryptBlock(cipher_block,sub_keys3,plain_block);

        //第二重
        des::DES_EncryptBlock(plain_block,sub_keys2,temp);

        //第一重
        des::DES_EncryptBlock(temp,sub_keys1,plain_block);
    }


}