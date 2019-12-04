#include <iostream>
#include <cstring>
using namespace std;

// ֤�����ݽṹ�� 
struct TbsCertificate {
	string version;		// �汾�� 
	string serialNumber;	// ���к� 
    string signature[2];	//�㷨OID���㷨���� 
    // ֤��ǩ���˺�������������ͣ�OID��������ֵ��STRING�� 
    string issuer[6][2];
    string subject[6][2];
    string validity[2];		// ��Ч�ڣ���ֹʱ��+��ֹʱ�� 
	string subjectPublicKeyInfo[3];// algorithm parameters Public-key
	string issuerUniqueID;	// ǩ����Ψһ��ʶ������ѡ�� 
	string subjectUniqueID;	// ����Ψһ��ʶ������ѡ�� 
	string extensions;		// ������ 
};

// ֤������ṹ 
struct X509cer{
	struct TbsCertificate cer_cnt; // ֤������ 
	string sig_alg[2];		//  ǩ���㷨���㷨OID+�㷨���� 
	string sig_val;	// ǩ��ֵ 
};
// ǩ���㷨OID���㷨���� 
string sa[8][2] = {
	{"1.2.840.10040.4.1", "DSA"},
	{"1.2.840.10040.4.3", "SHA1withDSA"},
	{"1.2.840.113549.1.1.1", "RSA"},
	{"1.2.840.113549.1.1.2", "MD2withRSA"},
	{"1.2.840.113549.1.1.3", "MD4withRSA"},
	{"1.2.840.113549.1.1.4", "MD5withRSA"}, 
	{"1.2.840.113549.1.1.5", "SHA1withRSA"},
	{"1.2.840.113549.1.1.11", "SHA256withRSA"}
};

// issuer��subject��OID�Ͷ�Ӧ�ĺ���
string issu[6][2] = {
	{"2.5.4.6", "Country(C)"},	// ���� 
	{"2.5.4.8", "Sate or Province Name(S)"},	// ��/ʡ�� 
	{"2.5.4.7", "Locality(L)"},	// ������ 
	{"2.5.4.10", "Organization Name(O)"},		// ��֯�� 
	{"2.5.4.11", "Organizational Unit Name(OU)"},	// ��֯��λ��
	{"2.5.4.3", "Common Name(CN)"} 	// ͨ���� 
};

string s = "";  // �洢�ļ����ݵ��ַ���
int time;   // ��ʾTLV�ݹ�ƥ��Ĵ���
int index; // ���ڰ�֤��issuer��subject���Ե����� 
bool flag = 1; // ���ڱ�־֤��󶨣�0�������
bool btag = 1;	//0-��ʽ  1-��ʽ 
FILE *fp;
X509cer cer;

/*order��ʾ֤��ṹ�󶨵�˳�� 
 *order = 1��version 
 *order = 2��serialNumber
 *order = 3��signature��algorithm+parameters
 *order = 4��issuer���������ͣ�OID��+����ֵ 
 *order = 5��validity 
 *order = 6��subject
 *order = 7��subjectPublicKeyInfo��algorithm+parameters+Public Key 
 *order = 8��Certificate Signature Algorithm + Certificate Signature 
*/ 
int order = 1;

/*��֤�����Ϣ
 *t��ʾ�ڼ��ε���tlv
*/
void bind(int t){ 
	// �汾�� 
    if(order == 1 && t == 2){
        if(s == "0" )
        	cer.cer_cnt.version = "V1";
        else if(s == "1")
        	cer.cer_cnt.version = "V2";
        else
         	cer.cer_cnt.version = "V3";
        order++;
	}
	// ���к� 
    else if(order == 2 || t == 2){
    	order++;
    	cer.cer_cnt.serialNumber = s;
    }
    // ǩ���㷨�� 
    else if(order == 3 && t == 6){
    	// ����ǩ���㷨OID��ƥ��֤����㷨�� 
    	for(int i = 0; i < 8; ++i){
            if(s == sa[i][0]){
                cer.cer_cnt.signature[0] = sa[i][1];
                break;
            }
     	}
    }
    // ǩ���㷨���� 
    else if(order == 3 && t == 5){
    	cer.cer_cnt.signature[1] = s;
    	order++;
    }
    // ֤��ǩ������������ 
    else if(order == 4 && t == 6){
        // ����OID�뺬��ƥ���
    	for(int i = 0; i < 6; ++i){
            if(s == issu[i][0]){
                cer.cer_cnt.issuer[i][0] = issu[i][1];
                //cer.cer_cnt.issuer[i][0] += "of issuer:\t";
                index=i;
                break;
            }
        }
    }
    // ֤��ǩ��������ֵ 
    else if(order == 4 && t == 19) 
        cer.cer_cnt.issuer[index][1] = s;
    
	// ��Ч�� 
    else if(t == 23){
        char tmp[19] = {'2', '0', s[0], s[1], '.', s[2], s[3], '.', s[4], s[5], ' ', s[6], s[7], ':', s[8], s[9], ':', s[10], s[11]};
        cer.cer_cnt.validity[order-4] = tmp;
    	order++;
    }
    // ֤��������������
    else if(order == 6 && t == 6){
            // ����OID�뺬��ƥ���
    		for(int i = 0; i < 6; ++i){
                if(s == issu[i][0]){ 
                    cer.cer_cnt.subject[i][0] = issu[i][1];
                    //cer.cer_cnt.subject[i][0] += "of subject:\t";
                    index=i;
                    break;
                }
        	}
            // ����OID�㷨����ȡ���幫Կ��Ϣ���㷨��
    		for(int i = 0; i < 8; ++i){
            	if(s == sa[i][0]){
             	    cer.cer_cnt.subjectPublicKeyInfo[0] = sa[i][1];
             	    order++;
            	    break;
           		}
        	}      
    }
    // ��������ֵ�����֣�
    else if(order == 6 && (t == 12 || t == 19))
		cer.cer_cnt.subject[index][1] = s;
    // ���幫Կ����
    else if(order == 7 && t == 5)
		cer.cer_cnt.subjectPublicKeyInfo[1] = s;
    // ���幫Կ
    else if(order == 7 && t == 3)
        cer.cer_cnt.subjectPublicKeyInfo[2] = s;
    // ǩ���㷨��
    else if(order == 7 && t == 6){
    	order++;
    	for(int i = 0; i < 8; ++i){
            if(s == sa[i][0]){
                cer.sig_alg[0] = sa[i][1];
                break;
            }
        }
    }
    // ǩ���㷨����
    else if(order == 8 && t == 5)
    	cer.sig_alg[1] = s;
    // ǩ��ֵ
    else if(order == 8 && t == 3){
    	cer.sig_val = s;
        flag = 0;
    } 
}
// ���ļ��ж�ȡ�ַ�������ֵ��s
void getStr(int len){
    s = ""; 
    int i = 0;
    for(int i = 0; i < len; ++i){
        unsigned char tl = fgetc(fp);
        char ts2[10];
        sprintf(ts2, "%02x", (int)tl);
        s = s + ts2;
    }
}

// ��ӡ֤������ 
void printCer(){
	cout << "***** X.509 Certificate Resolution *****" << endl;
	cout << "***** 	    By: luji17343080 	   *****\n " << endl;
    cout << "Version: "<< cer.cer_cnt.version << endl;
    cout << "Serial Number: "<< cer.cer_cnt.serialNumber << endl;
    cout << "Algorithm of signature:	" << cer.cer_cnt.signature[0] << endl;
    cout << "Parameters of signature: "<< cer.cer_cnt.signature[1] << endl;
    cout << "Issuer:" << endl;
		for(int i = 0; i < 6; ++i){
			if(cer.cer_cnt.issuer[i][0] == "")
				continue; 
			cout << "	" << cer.cer_cnt.issuer[i][0] << ": " << cer.cer_cnt.issuer[i][1] << endl;
		}
	cout << "Validity:" << endl;
	cout << "	Begin: " << cer.cer_cnt.validity[0] << endl;
	cout << "	End: " << cer.cer_cnt.validity[1] << endl;
    cout << "Subject:" << endl;
		for(int i = 0; i < 6; ++i){
			if(cer.cer_cnt.subject[i][0] == "")
				continue;
			cout << "	" << cer.cer_cnt.subject[i][0] << ": " << cer.cer_cnt.subject[i][1] << endl;
		}
	cout << "Public Key Algorithm: " << cer.cer_cnt.subjectPublicKeyInfo[0] << endl;
    cout << "Public Key Parameters: " << cer.cer_cnt.subjectPublicKeyInfo[1] << endl;
    cout << "Subject Public Key:\n	" << cer.cer_cnt.subjectPublicKeyInfo[2]<< endl << endl;
    cout << "Issuer Unique Identifier: NULL" << endl;
	cout << "Subject Unique Identifier: NULL" << endl;
	cout << "Extensions: omission" << endl; 
    cout << "Certificate Signature Algorithm: " <<  cer.sig_alg[0] << endl;
    cout << "Parameters of Certificate Signature Algorithm: " << cer.sig_alg[1] << endl << endl;
    cout << "Certificate Signature:\n	" << cer.sig_val << endl;
}
 
// TLVƥ��ĵݹ飨�ο����ϲ��ͣ�https://www.cnblogs.com/jiu0821/p/4598352.html��
int tlv(){
    if(flag==0) {
    	return 1000;
    } 
    time++;     // �ݹ������1
    bool flag1 = true;
    unsigned char type = fgetc(fp); // �ļ��е�����ֵ
    unsigned char len_ = fgetc(fp);	//  ֵ�ĳ��� 
    int len = len_;
    s = "";
    if(type < 0xa0){
    	if(type == 1){
    		unsigned char vc = fgetc(fp);
            s = vc == 0 ? "FALSE" : "TRUE";
    	}
    	else if(type == 2 || type == 3 || type == 4){
    		if(len_ > 0x80){
	            len = 0;
	            for(int i = 0; i < len_-0x80; ++i)
	                len = len * 256 + fgetc(fp);
	    	}
            getStr(len);
        }
        else if(type==5){
            s = "NULL";
        }
		else if(type == 6){
            int d = fgetc(fp);
            char ts2[10];
            sprintf(ts2,"%d",d/40);
            s = s + ts2 + ".";
            sprintf(ts2,"%d",d-d/40*40);
            s = s + ts2;
            for(int i = 1; i < len_; ++i){
                i--;
                int t = 0;
                while(1){
                    int tl = fgetc(fp);
                    i++;
                    bool b2 = false;
                    if(tl & 0x80){
                        b2=true;
                        tl &= 0x7f;
                    }
                    t = t * 128 + tl;
                    if(!b2) break;
                }
                sprintf(ts2,"%d",t);
                s = s + "." + ts2;
            }
        }
		else if(type == 0x13 || type == 0x17 || type == 0x18 || type == 0x0c){
            char ss[5000];
            fread(ss, 1, len_, fp);
            ss[len_] ='\0';
            s = ss;
        }
		else if(type == 0x30 || type == 0x31){
            flag1 = false;
            if(len_ > 0x80){
                len = 0;
                len_ -= 0x80;
                unsigned char tl;
				for(int i = 0; i < len_; ++i){
                    tl = fgetc(fp);
                    len = len * 256 + tl;
                }
            }
            int dlen = len;
            while(dlen>0){
                dlen -= tlv();
            }
        }
		else{
            printf("the cer has errors!\n");
            return len;
        }
    }
    else{
        flag1 = false;
        if(type == 0xff){
        	printCer();
        	exit(1);
        }
        if(len_ > 0x80){ 
            int tn2 = len_-0x80;
            unsigned char tl;
            len = 0;
            for(int i = 0; i < tn2; ++i){
                tl = fgetc(fp);
                len = len * 256 + tl;
            }
        }
        if(btag){
            if(time == 67)  
				fseek(fp,len,SEEK_CUR);
            else    
				tlv();
        }
    }
    if(flag1)
    	bind(type);
    return len;
}

int main(){
	char *filename="ca.cer";
	fp=fopen(filename,"rb");
 	if(fp==NULL) {
 		puts("can't open the file!");
 		exit(0);
	}
	tlv();		// TLVƥ��ݹ� 
	printCer(); 	// ��ӡ֤������� 
}
