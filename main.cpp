#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <bitset>
#include <algorithm>
#include <math.h>
#include <iterator>
#include <sstream>
using namespace std;

/*Env variables*/
const string ROOT_DIR = "/home/fengkiej/Documents/PrakASD/DESImplementation/";
const string EBIT = "e-bit.txt";
const string INIT_PERMUTATION = "ip.txt";
const string INIT_PERMUTATION_INV = "ip-1.txt";
const string PC1 = "pc1.txt";
const string PC2 = "pc2.txt";
const string PERMUTATION = "permutation.txt";
const string SBOX1 = "sbox1.txt";
const string SBOX2 = "sbox2.txt";
const string SBOX3 = "sbox3.txt";
const string SBOX4 = "sbox4.txt";
const string SBOX5 = "sbox5.txt";
const string SBOX6 = "sbox6.txt";
const string SBOX7 = "sbox7.txt";
const string SBOX8 = "sbox8.txt";
const char SHIFTS[] = {0, 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28};

/*Methods -> General*/
vector<char> vectorLo(vector<char>&);
vector<char> vectorHi(vector<char>&);
vector<char> strToBinary(string&);
vector<char> addPadding(vector<char>&);
vector<char> rearrangeVector(vector<char>&, const string&, int);
vector<char> xorVect(vector<char>&, vector<char>&);
vector<char> decToBin(int&);
vector<char> setToPrintableAscii(vector<int>&);
string binToStr(vector<char>&);
void printVector(vector<char>&);
char xorChr(char&, char&);
int binToDec(vector<char>&);

/*Methods -> Generating Key*/
vector<char> generateKPlus(vector<char>&);
vector<char> generateKn(int, vector<char>&);
void shiftLeft(vector<char>&, int);

/*Methods -> Message Encryption/Decryption*/
vector<char> initialPermutation(vector<char>&);
vector<char> feistel(vector<char>&, vector<char>&);
vector<char> expand(vector<char>&);
vector<char> subvectToSBoxN(int&, vector<char>&);
vector<char> putToSBoxes(vector<char>&);
vector<char> invInitialPermutation(vector<char>&);
vector<char> rounds(vector<char>&, vector<char>&);
vector<char> DESencrypt(string&, string&);
string getSBox(int&);
int getSBoxVal(string, int&, int&);

int main(int argc, char **argv)
{
	string key; 
	string plaintext; 
	
	cout << "Key (must be =< 8 characters): ";
	cin >> key;
	
	cout << "Plaintext: ";
	cin >> plaintext;
	
	int s = 0, e = 8;
	for(int i = 0; i <= plaintext.size()/8; i++){
		string substring(plaintext.begin()+s, plaintext.end()+e);
		vector<char> cipherText = DESencrypt(key, substring);
		printVector(cipherText);
		
		s+=8; e+=8;
	}
	cout << endl;
	
	//TODO: This code can be made more efficient using pointers and deque!
	return 0;
}

template <typename T> vector<T> concat(vector<T>& a, vector<T>& b) {
    vector<T> vNew = vector<T>();
    copy(a.begin(), a.end(), back_inserter(vNew));
    copy(b.begin(), b.end(), back_inserter(vNew));
	
    return vNew;
}

void printVector(vector<char>& v){
	for (vector<char>::const_iterator i = v.begin(); i != v.end(); ++i){
		cout << *i;
	}
}

vector<char> strToBinary(string& text){
	int textLength = text.size();
	string bits;
	for(int i = 0; i < textLength; i++){
		bits += bitset<8>(text[i]).to_string();
	}
	
	return vector<char>(bits.begin(), bits.end());
}

vector<char> addPadding(vector<char>& v){
	while(v.size() % 64 != 0) v.push_back('0');
	
	return v;
}

/*splitting vector by copying into two arrays. This takes O(n), there's might be a better way*/
vector<char> vectorLo(vector<char>& v){
	const int mid = v.size()/2;
	
	return vector<char>(v.begin(), v.begin()+mid);
}

vector<char> vectorHi(vector<char>& v){
	const int mid = v.size()/2;
	
	return vector<char>(v.begin()+mid, v.end());
}


char xorChr(char& a, char& b){
	return !(a == b)? '1':'0';
}

vector<char> xorVect(vector<char>& a, vector<char>& b){
	int length = 0;
	vector<char> newV;
	
	if (a.size() > b.size()){
		length = a.size();
	} else {
		length = b.size();
	}
	
	for(int i = 0; i < length; i++){
		newV.push_back(xorChr(a[i], b[i]));
	}
	
	return newV;
}

vector<char> generateKPlus(vector<char>& v){
	return rearrangeVector(v, PC1, 56);
}

void shiftLeft(vector<char>& v, int shifts){
	rotate(v.begin(), v.begin() + shifts, v.end());
}

vector<char> generateKn(int n, vector<char>& v){
	vector<char> C = vectorLo(v);
	vector<char> D = vectorHi(v);
	
	shiftLeft(C, SHIFTS[n]);
	shiftLeft(D, SHIFTS[n]);
	
	vector<char> CnDn = concat(C, D);
	
	return rearrangeVector(CnDn, PC2, 48);
}

vector<char> rearrangeVector(vector<char>& v, const string& filename, int size){
	vector<char> vNew(size);
	int i = 0;
	int index;
	
	fstream open((ROOT_DIR+filename).c_str());
	while(open >> index){
		vNew[index - 1] = v[i];
		i++;
	}
	
	return vNew;
}

vector<char> initialPermutation(vector<char>& v){
	return rearrangeVector(v, INIT_PERMUTATION, 64);
}

vector<char> rounds(vector<char>& v, vector<char>& kPlus){
	vector<char> L = vectorLo(v);
	vector<char> R = vectorHi(v);
	
	for(int i = 1; i <= 16; i++){
		vector<char> Ln, Rn, Kn, f;
		Kn = generateKn(i, kPlus);
		Ln = R;
		f = feistel(R, Kn);
		Rn = xorVect(L, f);
		
		L = Ln;
		R = Rn;
	}
	
	return concat(R, L);
}

vector<char> feistel(vector<char>& v, vector<char>& K){
	vector<char> eV = expand(v);
	vector<char> B = xorVect(K, eV);
	vector<char> SB = putToSBoxes(B);
	
	return rearrangeVector(SB, PERMUTATION, 32);
}

vector<char> expand(vector<char>& v){
	return rearrangeVector(v, EBIT, 48);
}

/*convert bin of 4 bits to dec*/
int binToDec(vector<char>& v){
	int dec = 0; int powerOf = 0;
	for(int i = 3; i >= 0; i--){
		dec += (v[i] - 48) * pow(2, powerOf);
		powerOf++;
	}
	
	return dec;
}

/*convert dec to binary of 4 bits*/
vector<char> decToBin(int& n){
	vector<char> bin(4);
	for(int i = 0; i < 4; i++){
		char bit;
		(n % 2)? bit = '1':bit = '0';
		bin.insert(bin.begin(), bit);
		
		n /= 2;
	}
	
	return bin;
}

vector<char> putToSBoxes(vector<char>& v){
	vector<char> newV;
	int s = 0; int e = 6;
	for(int i = 1; i <= 8; i++){
		vector<char> subvect(v.begin()+s, v.begin()+e);
		vector<char> SnBn = subvectToSBoxN(i, subvect);
		newV = concat(newV, SnBn);
		s += 6; e += 6; //increase starting and end by 6
	}
	
	return newV;
}

vector<char> subvectToSBoxN(int& n, vector<char>& v){
	string SBOX = getSBox(n);
	vector<char> ctrlBits;
	vector<char> midBits;
	
	ctrlBits.push_back('0'); //padding to make it in 4 bits
	ctrlBits.push_back('0');
	ctrlBits.push_back(v[0]);
	ctrlBits.push_back(v[5]);
	
	for(int i = 1; i <= 4; i++){
		midBits.push_back(v[i]);
	}

	int row = binToDec(ctrlBits);
	int col = binToDec(midBits);
	
	int sBoxVal = getSBoxVal(SBOX, row, col);
	
	return decToBin(sBoxVal);
}

string getSBox(int& n){
	switch(n){
		case 1:
			return SBOX1;
		break;
		case 2:
			return SBOX2;
		break;
		case 3:
			return SBOX3;
		break;
		case 4:
			return SBOX4;
		break;
		case 5:
			return SBOX5;
		break;
		case 6:
			return SBOX6;
		break;
		case 7:
			return SBOX7;
		break;
		case 8:
			return SBOX8;
		break;
	}
}

int getSBoxVal(string SBOX, int& row, int& col){
	ifstream infile((ROOT_DIR+SBOX).c_str());
	int index = (row*16) + col;
	int x = 0;
	
	for(int i = 0; i <= index && infile >> x; i++);
	
	return x;
}

vector<char> invInitialPermutation(vector<char>& v){
	return rearrangeVector(v, INIT_PERMUTATION_INV, 64);
}

vector<int> binToInt(vector<char>& v){
	string str(v.begin(), v.end());
	stringstream sstream(str);
	vector<int> output;
	
	while(sstream.good()){
        std::bitset<8> bits;
        sstream >> bits;
        int c = bits.to_ulong();
        output.push_back(c);
    }
	
	return output;
}

vector<char> setToPrintableAscii(vector<int>& v){
	v.pop_back(); //because it was a string, and we want to get rid the delim
	
	vector<char> newV;
	for(int i = 0; i < v.size(); i++){
		v[i] = (v[i] % 95) + 32;
		newV.push_back(v[i]);
	}
	
	return newV;
}

vector<char> DESencrypt(string& key, string& plaintext){
	vector<char> binKey = strToBinary(key);
				 binKey = addPadding(binKey);
	vector<char> kPlus = generateKPlus(binKey);
 	vector<char> binPlaintext = strToBinary(plaintext);
				 binPlaintext = addPadding(binPlaintext);
	vector<char> IP = initialPermutation(binPlaintext);
	vector<char> roundResult = rounds(IP, kPlus); 
	vector<char> IPInv = invInitialPermutation(roundResult);
	vector<int>  asciiSet = binToInt(IPInv);
	vector<char> cipherText = setToPrintableAscii(asciiSet);
	
	return cipherText;
}