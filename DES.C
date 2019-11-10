#include <fstream>
#include <algorithm>
using namespace std;
typedef long long block;
class DES
{
	block M, K, E, k[17];
	int pc1[56], pc2[48], ip[64], p[32], ipinv[64], ebitselection[48], shifts[16], hex2int[256], int2hex[16], sbox[8][4][16];
public:
	DES();
	block blockify(string);
	string stringify(block);
	block permute(block, int*, int, int);
	void genKey(string);
	block f(block, block);
	string encrypt(string, string);
	string decrypt(string, string);
};

DES::DES()
{
	// Ready up hex2int, int2hex which is used to convert string input to binary and reverse
	int i, j, l;
	ifstream fin;
	for(i = 0; i < 10; i++)
	{
		hex2int[i+'0'] = i;
		int2hex[i] = i+'0';
	}
	for(i = 10; i < 16; i++)
	{
		hex2int[i-10+'A'] = i;
		int2hex[i] = i-10+'A';
	}
	// Load permutations from files
	fin.open("PermutationBoxes/PC1");
	for(i = 0; i < 56; i++)
	{
		fin>>pc1[i];
	}
	fin.close();
	fin.open("PermutationBoxes/SHIFTS");
	for(i = 0; i < 16; i++)
	{
		fin>>shifts[i];
	}
	fin.close();
	fin.open("PermutationBoxes/PC2");
	for(i = 0; i < 48; i++)
	{
		fin>>pc2[i];
	}
	fin.close();
	fin.open("PermutationBoxes/IP");
	for(i = 0; i < 64; i++)
	{
		fin>>ip[i];
	}
	fin.close();
	fin.open("PermutationBoxes/EBITSELECTION");
	for(i = 0; i < 48; i++)
	{
		fin>>ebitselection[i];
	}
	fin.close();
	fin.open("PermutationBoxes/SBOX");
	for(i = 0; i < 8; i++)
	{
		for(j = 0; j < 4; j++)
		{
			for(l = 0; l < 16; l++)
			{
				fin>>sbox[i][j][l];
			}
		}
	}
	fin.close();
	fin.open("PermutationBoxes/P");
	for(i = 0; i < 32; i++)
	{
		fin>>p[i];
	}
	fin.close();
	fin.close();
	fin.open("PermutationBoxes/IP-1");
	for(i = 0; i < 64; i++)
	{
		fin>>ipinv[i];
	}
	fin.close();
}
block DES::blockify(string s)
{
	int i, n = s.length();
	block b = 0;
	for(i = 0; i < n; i++)
	{
		b = (b<<4);
		b = b|hex2int[s[i]];
	}
	return b;
}
string DES::stringify(block b)
{
	int i, j, mask = 15;
	string s;
	for(j = 0; j < 16; j++)
	{
		i = mask & b;
		s.push_back(int2hex[i]);
		b = (b>>4);
	}
	reverse(s.begin(), s.end());
	return s;
}
block DES::permute(block m, int pc[], int psize, int bitsize)
{
	// block to be permuted is m
	// pc is the permutation array
	// psize is the size of permutation array
	// bitsize is the size of m
	int i;
	block b = 0, mask;
	for(i = 0; i < psize; i++)
	{
		mask = (1LL<<(bitsize-pc[i]));
		if(m & mask)
		{
			b = b|1;
		}
		if(i < psize-1)
		{
			b = (b<<1);
		}
	}
	return b;
}
void DES::genKey(string key)
{
	int i, j, shift;
	block b = 0, mask, cidi, c[17], d[17];
	K = blockify(key);
	K = permute(K, pc1, 56, 64);
	d[0] = ((1LL<<28)-1)&K;
	c[0] = ((1LL<<28)-1)&(K>>28);
	for(i = 1; i < 17; i++)
	{
		shift = shifts[i-1];
		d[i] = d[i-1]; c[i] = c[i-1];
		d[i] = d[i]<<shift; c[i] = c[i]<<shift;
		mask = shift == 1 ? 1 : 3;
		mask = mask<<28;
		b = d[i] & mask;
		d[i] = b ^ d[i];
		b = b>>28;
		d[i] = d[i] | b;
		b = c[i] & mask;
		c[i] = b ^ c[i];
		b = b>>28;
		c[i] = c[i] | b;
	}
	for(i = 0; i < 17; i++)
	{
		cidi = (c[i]<<28) | d[i];
		b = 0;
		for(j = 0; j < 48; j++)
		{
			mask = (1LL<<(56-pc2[j]));
			if(cidi & mask)
			{
				b = b|1;
			}
			b = (b<<1);
		}
		k[i] = permute(cidi, pc2, 48, 56);
	}
}
block DES::f(block r, block k)
{
	block b = 0, mask = 63, sextet;
	int i, row, col, shift = 0;
	r = permute(r, ebitselection, 48, 32);
	r = r ^ k;
	for(i = 7; i >= 0; i--)
	{
		sextet = mask & r;
		row = ((sextet & 32)>>4)|(sextet & 1);
		col = (sextet & 30)>>1;
		b = b|(sbox[i][row][col]<<shift);
		shift = shift+4;
		r = (r>>6);
	}
	b = permute(b, p, 32, 32);
	return b;
}
string DES::encrypt(string plaintext, string key)
{
	int i;
	block l[17], r[17], rl;
	genKey(key);
	M = blockify(plaintext);
	M = permute(M, ip, 64, 64);
	r[0] = ((1LL<<32)-1)&M;
	l[0] = ((1LL<<32)-1)&(M>>32);
	for(i = 1; i < 17; i++)
	{
		l[i] = r[i-1];
		r[i] = l[i-1] ^ f(r[i-1], k[i]);

	}
	rl = (r[16]<<32)|l[16];
	E = permute(rl, ipinv, 64, 64);
	return stringify(E);
}
string DES::decrypt(string ciphertext, string key)
{
	int i;
	block l[17], r[17], rl;
	genKey(key);
	reverse(k+1, k+17);
	M = blockify(ciphertext);
	M = permute(M, ip, 64, 64);
	r[0] = ((1LL<<32)-1)&M;
	l[0] = ((1LL<<32)-1)&(M>>32);
	for(i = 1; i < 17; i++)
	{
		l[i] = r[i-1];
		r[i] = l[i-1] ^ f(r[i-1], k[i]);

	}
	rl = (r[16]<<32)|l[16];
	E = permute(rl, ipinv, 64, 64);
	return stringify(E);
}
