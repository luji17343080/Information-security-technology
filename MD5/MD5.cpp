#include <iostream>
#include <vector>
#include <cstdlib>
#include <string>
#include <fstream>
using namespace std;

//T��64��32-bit��(unsigned int),��16��������ʾ
const unsigned int T[64] = {
	0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
	0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
	0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
	0x6b901122,0xfd987193,0xa679438e,0x49b40821,
	0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
	0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
	0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
	0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
	0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
	0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
	0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
	0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
	0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
	0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
	0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
	0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

//S��64�ε���ѭ������λ����
const unsigned int s[64] = {
	7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
	5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
	4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
	6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

//X[k]��64�ε����õ�ÿ�����ݵĵ�k���ֵ�������
const unsigned int k[64] = {
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
	1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
	5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
	0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

const char Hex[] = "0123456789abcdef";

//�������Ĵ���
unsigned int A = 0x67452301;
unsigned int B = 0xefcdab89;
unsigned int C = 0x98badcfe;
unsigned int D = 0x10325476;

int L; //����
string plain = "";	//����
string cipher;	//����	

/*
��32-bit��Ϊ��λ�洢��������Ϣvector
ÿ��Ϊ512-bits = 16 * 32-bits
����ΪL
*/
vector<unsigned int> p(L * 16);

unsigned int X[16]; //ÿһ��512-bit������32-bit��Ϊ��λ��Ϊ16�����X��

/* ��һ��ѭ������F */
unsigned int F(unsigned int b, unsigned int c, unsigned int d) {
	return (b & c) | ((~b) & d);
}
/* �ڶ���ѭ������G */
unsigned int G(unsigned int b, unsigned int c, unsigned int d) {
	return (b & d) | (c & (~d));
}
/* ������ѭ������H */
unsigned int H(unsigned int b, unsigned int c, unsigned int d) {
	return b ^ c ^ d;
}
/* ������ѭ������I */
unsigned int I(unsigned int b, unsigned int c, unsigned int d) {
	return c ^ (b | (~d));
}

/* ������ */
void padding(string s) {
	/*
	512-bitΪһ�飬ÿһ���ַ�Ϊ8-bits
	�ַ�����λ��Ϊ�ַ������ȳ���8
	������ַ�����Ϊ�����֣�ԭ����K-bits + ������P-bits + 64 bits
	����ַ�����32-bit��Ϊ��λ��unsigned int����������������p��
	*/
	int bitCount = (s.length() * 8 + 64) % 512 == 0 ? 512 : 448 - (s.length() * 8) % 512; //�ʼ����P��λ��
	L = ((bitCount + s.length() * 8) + 64) / 512; //����Ϊ�������λ������512
	p.resize(L * 16); //��Ҫ���¶���p�Ĵ�С
	for (int i = 0; i < s.length(); i++) {
		p[i >> 2] |= (int)(s[i]) << ((i % 4) * 8); //1��unsigned int��Ӧ4��char
	}
	/* ���1000...000 */
	p[s.length() >> 2] |= 0x80 << ((s.length() % 4) * 8);

	/* ����64λ */
	p[p.size() - 2] = s.length() * 8;
}


/* ѭ������λ���� */
unsigned int left_shift(unsigned int num, unsigned int digits) {
	return (num << digits) | (num >> (32 - digits));
}
/* ѭ��ѹ�� */
void cyclic_compress(unsigned int *X) {
	unsigned int a = A;
	unsigned int b = B;
	unsigned int c = C;
	unsigned int d = D;
	unsigned int tmp = 0;

	/* 4��ѭ����64�ε��� */
	for (int i = 0; i < 64; i++) {
		unsigned int g[4] = { F(b, c, d), G(b, c, d), H(b, c, d), I(b, c, d) }; //4��ѭ���ֱ�ʹ�õ��ֺ���g

		/* ������ѭ�������ֻ� */
		tmp = d;
		d = c;
		c = b;
		b = b + left_shift(a + g[i / 16] + X[k[i]] + T[i], s[i]);
		a = tmp;
	}
	A += a;
	B += b;
	C += c;
	D += d;
}

/* 32-bit�޷�������ת��Ϊ8λ16�����ַ��� */
string Uint32toHexStr(unsigned int num) {
	string result = "";
	for (int i = 0; i < 4; i++) {
		string tmp = "";
		unsigned int hex_ = (num >> (i * 8)) % (1 << 8) & 0xff; //16����ת��
		for (int j = 0; j < 2; j++) {
			tmp = Hex[hex_ % 16] + tmp; //charתstring,ע��ӵ�˳�����෴
			hex_ /= 16;
		}
		result += tmp;
	}
	return result;
}

/* ���ܺ��� */
void encrypt(string s) {
	padding(s); //���
	/* ��ÿ����������ݣ���L�飩����4��ѭ����64�ε�����ѹ���������Ϊ��һ�ε��������� */
	for (unsigned int i = 0; i < L; i++) {
		for (int j = 0; j < 16; j++) {
			X[j] = p[i * 16 + j];
		}
		cyclic_compress(X);  //ѭ��ѹ��
	}
	cipher = Uint32toHexStr(A) + Uint32toHexStr(B) + Uint32toHexStr(C) + Uint32toHexStr(D); //����Ϊ32λ16�����ַ���
}

int main() {
	ofstream oi, oo;	//�����ļ����������
	oi.open("plain.txt");
	oo.open("cipher.txt");
	cout << "Plaintext: " << endl;
	getline(cin, plain);
	oi << plain;   //������д��plain.txt��
	encrypt(plain);
	cout <<"------------------------------"<< endl << "Ciphertext: " << endl << cipher << endl;
	oo << cipher;	//������д��cipher.txt��
	oi.close();
	oo.close();
}