#include <iostream>  
#include <fstream>
#include <iostream>
#include <bitset>  
#include <string>
#include <memory.h>

using namespace std;

bitset<64> key;                // 64位密钥  
bitset<48> subkey[16];         // 存放16轮子密钥  

// IP置换表  
int IP[] = { 58, 50, 42, 34, 26, 18, 10, 2,
60, 52, 44, 36, 28, 20, 12, 4,
62, 54, 46, 38, 30, 22, 14, 6,
64, 56, 48, 40, 32, 24, 16, 8,
57, 49, 41, 33, 25, 17, 9, 1,
59, 51, 43, 35, 27, 19, 11, 3,
61, 53, 45, 37, 29, 21, 13, 5,
63, 55, 47, 39, 31, 23, 15, 7 };

//IP逆置换表  
int IP_1[] = { 40, 8, 48, 16, 56, 24, 64, 32,
39, 7, 47, 15, 55, 23, 63, 31,
38, 6, 46, 14, 54, 22, 62, 30,
37, 5, 45, 13, 53, 21, 61, 29,
36, 4, 44, 12, 52, 20, 60, 28,
35, 3, 43, 11, 51, 19, 59, 27,
34, 2, 42, 10, 50, 18, 58, 26,
33, 1, 41, 9, 49, 17, 57, 25 };

/* 子密钥生成过程 */
// 密钥K非校验位PC-1置换表  
int PC_1[] = { 57, 49, 41, 33, 25, 17, 9,
1, 58, 50, 42, 34, 26, 18,
10, 2, 59, 51, 43, 35, 27,
19, 11, 3, 60, 52, 44, 36,
63, 55, 47, 39, 31, 23, 15,
7, 62, 54, 46, 38, 30, 22,
14, 6, 61, 53, 45, 37, 29,
21, 13, 5, 28, 20, 12, 4 };

//子密钥生成时的循环左移位数，第1、2、9、16个子密钥左移一位，其他子密钥移两位  
int shift_left[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// PC-2压缩置换表，将循环左移后的16个56位密钥压缩成48位子密钥  
int PC_2[] = { 14, 17, 11, 24, 1, 5,
3, 28, 15, 6, 21, 10,
23, 19, 12, 4, 26, 8,
16, 7, 27, 20, 13, 2,
41, 52, 31, 37, 47, 55,
30, 40, 51, 45, 33, 48,
44, 49, 39, 56, 34, 53,
46, 42, 50, 36, 29, 32 };

/* Feistel轮函数 */
//E-扩展表，将32位L\R扩展至48位  
int E_ext[] = { 32, 1, 2, 3, 4, 5,
4, 5, 6, 7, 8, 9,
8, 9, 10, 11, 12, 13,
12, 13, 14, 15, 16, 17,
16, 17, 18, 19, 20, 21,
20, 21, 22, 23, 24, 25,
24, 25, 26, 27, 28, 29,
28, 29, 30, 31, 32, 1 };

//8个s盒，实现6->4位的压缩置换  
int S_BOX[8][4][16] = {
		//S1-BOX
		{
			{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
			{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
			{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
			{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
		},
		//S2-BOX
		{
			{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
			{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
			{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
			{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
		},
		//S3-BOX
		{
			{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
			{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
			{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
			{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
		},
		//S4-BOX
		{
			{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
			{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
			{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
			{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
		},
		//S5-BOX
		{
			{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
			{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
			{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
			{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
		},
		//S6-BOX
		{
			{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
			{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
			{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
			{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
		},
		//S7-BOX
		{
			{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
			{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
			{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
			{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
		},
		//S8-BOX
		{
			{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
			{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
			{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
			{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
		}
};

// P置换表，将S-BOX压缩后的串进行置换作为最终的轮函数结果  
int P[] = { 16, 7, 20, 21,
29, 12, 28, 17,
1, 15, 23, 26,
5, 18, 31, 10,
2, 8, 24, 14,
32, 27, 3, 9,
19, 13, 30, 6,
22, 11, 4, 25 };



/* Feistel轮函数f,输入32位串，和48位子密钥，返回一个32位的串 */
bitset<32> f(bitset<32> R, bitset<48> k) {
	bitset<48> ext_R; //扩展后的32位串
	// 第一步：E-扩展置换，将输入的32位串扩展至48位  
	for (int i = 0; i < 48; ++i)
		ext_R[47 - i] = R[32 - E_ext[i]];

	// 第二步：将扩展后的R与子密钥k异或  
	ext_R = ext_R ^ k; 

	// 第三步：S-BOX压缩转换，将48位的串转换为36位串  
	bitset<32> f_out; //f函数的最终输出

	int b = 0; //表示f_out每一位的序号
	for (int i = 0; i < 48; i = i + 6) { //循环将48位串分为8组，每组6位
		int row = ext_R[i] * 2 + ext_R[i + 5]; //用每组的第1位和第6位组成的二进制数转换成的十进制数作为行数，直接第一位的数×2加第六位数即可
		int col = ext_R[i + 1] * 8 + ext_R[i + 2] * 4 + ext_R[i + 3] * 2 + ext_R[i + 4]; //用每组的2、3、4、5位计算列数
		int num = S_BOX[i / 6][row][col]; //找出相应的S-BOX对应row和col的十进制数
		bitset<4> binary(num); //将十进制的num转化为4位的二进制数
		//将4位二进制数分别赋值给f_out对应的位
		f_out[b] = binary[0];
		f_out[b + 1] = binary[1];
		f_out[b + 2] = binary[2];
		f_out[b + 3] = binary[3];
		b += 4;
	}

	// 第四步：P-置换，得到f函数最后的输出  
	bitset<32> tmp = f_out;
	for (int i = 0; i < 32; ++i)
		f_out[i] = tmp[P[i] - 1]; //因为P置换表是从1开始，所以要减1

	return f_out;
}


/* 子密钥生成过程中的移位函数，输入28位的串以及移位的位数，输出28位的新串 */
bitset<28> leftshift(bitset<28> k, int shift_digit) {
	bitset<28> tmp = k;
	for (int i = 27; i >= 0; --i) {
		if (i - shift_digit < 0)
			k[i] = tmp[i - shift_digit + 28];
		else
			k[i] = tmp[i - shift_digit];
	}
	return k;
}


/* 子密钥生成 */
void sub_keys() {
	bitset<56> uncheckd_key; //去掉校验位的key
	bitset<28> C; //uncheckd_key的前28位
	bitset<28> D; //uncheckd_key的后28位
	bitset<48> sub_key; //48位子密钥
	//第一步：对key的非校验委进行PC-1置换  
	for (int i = 0; i < 56; ++i)
		uncheckd_key[55 - i] = key[64 - PC_1[i]];

	//生成16个48位子密钥，保存在subkeys[]中  
	for (int r = 0; r < 16; ++r) {

		for (int i = 0; i < 28; ++i)
			C[i] = uncheckd_key[i];
		for (int i = 28; i < 56; ++i)
			D[i - 28] = uncheckd_key[i];
		
		//第二步：根据shift_left数组规定的规则左移  
		C = leftshift(C, shift_left[r]);
		D = leftshift(D, shift_left[r]);

		//第三步：PC-2压缩置换，将56位uncheckd_key压缩成48位形成子密钥
		for (int i = 0; i < 28; ++i)
			uncheckd_key[i] = C[i];
		for (int i = 28; i < 56; ++i)
			uncheckd_key[i] = D[i - 28];
		
		for (int i = 0; i < 48; ++i)
			sub_key[i] = uncheckd_key[PC_2[i] - 1];

		subkey[r] = sub_key;
	}
}

/* DES加密，输入64位明文，返回64位密文 */
bitset<64> encrypt(bitset<64> & clear) {
	bitset<64> cipher; //密文
	bitset<64> Rep_clear; //IP置换后的明文
	bitset<32> L; //明文IP置换后前32位
	bitset<32> R; //明文IP置换后后32位
	bitset<32> L_; //迭代过程的下一轮L
	// 第一步：IP置换  
	for (int i = 0; i < 64; ++i)
		Rep_clear[i] = clear[IP[i] - 1]; //因为IP置换表中是从1开始，所以需要减1

	// 第二步：16轮迭代T置换得到L16，R16    
	for (int i = 0; i < 32; ++i) //得到L0
		L[i] = Rep_clear[i];
	for (int i = 32; i < 64; ++i) //得到R0
		R[i - 32] = Rep_clear[i];
	
	for (int r = 0; r < 16; ++r) { //根据迭代规则进行16轮迭代得到L16和R16
		L_ = R;
		R = L ^ f(R, subkey[r]);
		R = L_;
	}
	// 第四步：W置换生成R16L16，即前32位为R16，后32位为L16  
	for (int i = 0; i < 32; ++i)
		cipher[i] = R[i];
	for (int i = 32; i < 64; ++i)
		cipher[i] = L[i - 32];

	// 第五步：IP-1置换  
	Rep_clear = cipher;
	for (int i = 0; i < 64; ++i)
		cipher[i] = Rep_clear[IP_1[i] - 1];
 
	return cipher;
}

/* DES解密，输入64位密文，返回64位明文，与加密过程调度子密钥的顺序相反 */
bitset<64> decrypt(bitset<64> & cipher) {
	bitset<64> clear; //明文
	bitset<64> Rep_cipher; //IP置换后的密文
	bitset<32> L; //明文IP置换后前32位
	bitset<32> R; //明文IP置换后后32位
	bitset<32> L_; //迭代过程的下一轮L
	// 第一步：IP置换  
	for (int i = 0; i < 64; ++i)
		Rep_cipher[i] = cipher[IP[i] - 1]; //因为IP置换表中是从1开始，所以需要减1

	// 第二步：16轮迭代T置换得到L16，R16    
	for (int i = 0; i < 32; ++i) //得到L0
		L[i] = Rep_cipher[i];
	for (int i = 32; i < 64; ++i) //得到R0
		R[i - 32] = Rep_cipher[i];

	for (int r = 0; r < 16; ++r) { //根据迭代规则进行16轮迭代得到L16和R16，与加密调度顺序相反，从子密钥K16开始调度
		L_ = R;
		R = L ^ f(R, subkey[15 - r]); 
		R = L_;
	}
	// 第四步：W置换生成R16L16，即前32位为R16，后32位为L16  
	for (int i = 0; i < 32; ++i)
		clear[i] = R[i];
	for (int i = 32; i < 64; ++i)
		clear[i] = L[i - 32];

	// 第五步：IP-1置换  
	Rep_cipher = clear;
	for (int i = 0; i < 64; ++i)
		clear[i] = Rep_cipher[IP_1[i] - 1];

	return clear;
}

/* 将char变为二进制数 */
bitset<64> chartobitset(const char s[8]) {
	bitset<64> bits;
	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 8; ++j)
			bits[i * 8 + j] = ((s[i] >> j) & 1);
	return bits;
}

int main() {
	fstream file; 
	string str_clear; //字符串明文
	string str_key; //字符串密钥k
	cout << "待加密的内容：";
	cin >> str_clear;
	cout << "密钥：";
	cin >> str_key;
	string m = "00000000"; //8字节字符串
	key = chartobitset(str_key.c_str());
	// 生成16个子密钥  
	sub_keys();
	
	//将密文转换为字符串写入加密文件中
	file.open("加密文件.txt", ios::binary | ios::out | ios::end);
	for (int i = 0; i < str_clear.size() / 8; i++) {
		for (int j = 0; j < 8; j++)
			m[j] = str_clear[i * 8 + j];
		bitset<64> clear = chartobitset(m.c_str());
		cout << "二进制明文：" << clear << endl; 
		bitset<64> cipher = encrypt(clear);
		cout << "二进制密文：" << cipher << endl;
		file.write((char*)& cipher, sizeof(cipher));
	}
	file.close();

	// 读文件 a.txt 
	bitset<100000> encrypttxt; //存放加密文件的位组
	bitset<64> temp;
	file.open("加密文件.txt", ios::binary | ios::in);
	file.read((char*)& encrypttxt, sizeof(encrypttxt)); //将加密文件
	file.close();
	file.open("解密文件.txt", ios::binary | ios::out | ios::end);
	//将解密后的明文写入解密文件中
	for (int k = 0; k < str_clear.size() / 8; k++) {
		for (int h = 0; h < 64; h++)
			temp[h] = encrypttxt[k * 64 + h];
		bitset<64> out_clear = decrypt(temp);
		cout << "解密的二进制明文：" << out_clear << endl;
		file.write((char*)& out_clear, sizeof(out_clear));
	}
	file.close();

	for (int i = 0; i < 16; i++) {
		cout << "子密钥" << i + 1 << ": " << subkey[i] << endl;
	}
	return 0;
}
