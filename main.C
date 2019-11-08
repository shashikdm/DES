#include <iostream>
#include <chrono>
#include "DES.C"
using namespace std;
using namespace std::chrono;
string toupper(string &s)
{
	for_each(s.begin(), s.end(), [](char & c)
	{
		c = toupper(c);
	});
}
int main()
{
	DES E;
	string key, plaintext, ciphertext;
	cout<<"Enter 16 hexadecimal digit plaintext: ";
	cin>>plaintext;
	toupper(plaintext);
	cout<<"Enter 16 hexadecimal digit key: ";
	cin>>key;
	toupper(key);
	auto start = high_resolution_clock::now(); 
	ciphertext = E.encrypt(plaintext, key);
	plaintext = E.decrypt(ciphertext, key);
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start); 
	cout<<"Ciphertext: "<<ciphertext<<'\n';
	cout<<"Decrypted plaintext: "<<plaintext<<'\n';
	cout<<"Time taken to encrypt and decrypt (in microseconds): "<<duration.count()<<'\n'; 
	return 0;
}