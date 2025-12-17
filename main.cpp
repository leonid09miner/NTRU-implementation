#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <stdexcept>
#include <sodium.h>
#include <chrono>
#include "sha256.h"

using namespace std;

class Polynomial
{
public:
	int* pol;
	int deg;
	
	template <size_t len>
	Polynomial(const int (&arr)[len]);
	Polynomial(const int* = NULL, int = 0);
	Polynomial(int);
	Polynomial(const Polynomial& other);
	~Polynomial();

	string pol_to_string(int = 0);

	friend ostream& operator<<(ostream& os, const Polynomial& pol);
	
	Polynomial& operator=(const Polynomial&);
	int& operator[](int);

	friend Polynomial operator+(const Polynomial&, const Polynomial&);
	friend Polynomial operator+(const Polynomial&, int);
	friend Polynomial operator-(const Polynomial&, const Polynomial&);
	friend Polynomial operator*(const Polynomial&, const Polynomial&);
	friend Polynomial operator*(const Polynomial&, int);
	friend Polynomial operator*(int, const Polynomial&);
	friend Polynomial operator%(const Polynomial&, int);
};

int inverseInteger(int num, int mod);
// Polynomial mod_div(const Polynomial& pol1, const Polynomial& pol2, int mod);
int eucl_inverse_mod(Polynomial pol, int mod, Polynomial *inv);
int eucl_inverse_mod2k(Polynomial pol, int mod, Polynomial *inv);
Polynomial eucl_inverse(Polynomial pol, int mod);
// Polynomial generate_ternary_poly(int deg, int num_ones, int num_neg);
vector<Polynomial> generate_ntru_key(int deg, int p, int q, int d);
vector<Polynomial> str_to_polyv(const string& msg, int deg);
Polynomial data_to_poly(const unsigned char* msg, int len, int deg);
Polynomial hash_to_poly(const unsigned char* msg, int len, int deg);
unsigned char* poly_to_data(Polynomial poly, int len, int deg);
string polyv_to_str(const vector<Polynomial> poly_msg, int deg);
vector<Polynomial> ntru_encrypt(vector<Polynomial> data, Polynomial pub_key, int q, int dr);
vector<Polynomial> ntru_decrypt(vector<Polynomial> enc_data, Polynomial priv_f, Polynomial priv_fp, int q, int p);
unsigned char* padding_encode(string data, unsigned char* hash);
string padding_decode(unsigned char* enc_data);
Polynomial minimize(Polynomial poly, int mod);
// Polynomial random_blind(int deg);
void benchmark(const string& name, int iterations, void (*func)());
void test_operation();

int main()
{
	if (sodium_init() < 0) {
		throw runtime_error("libsodium init failed");
	}

	int p = 3;
	int q = 4096;
	int deg = 821;
	int d = 320;

	/* // test simplified encryption and decryption
	int qs = 32;
	Polynomial f({-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1});
	Polynomial fq;
	Polynomial fp;

	int ret = eucl_inverse_mod2k(f, qs, &fq);
	if (ret)
		return 1;
	ret = eucl_inverse_mod(f, p, &fp);
	if (ret)
		return 1;

	Polynomial g({-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1});

	Polynomial h = p * fq * g % qs;
	
	string msg = "message";

	vector<Polynomial> poly_msg = str_to_polyv(msg, 11);

	vector<Polynomial> enc = ntru_encrypt(poly_msg, h, qs, 2);

	for (int i = 0; i < enc.size(); i++)
		cout << enc[i] << endl;

	enc = ntru_decrypt(enc, f, fp, qs, p);

	for (int i = 0; i < enc.size(); i++)
		cout << enc[i] << endl;

	string data = polyv_to_str(enc, 11);
	cout << data << endl; 
	// */

	//* // test algorithm
	vector<Polynomial> key = generate_ntru_key(deg, p, q, d);

	Polynomial f = key[0], g = key[1], fp = key[2], fq = key[3];
	Polynomial h = p * fq * g % q;

	cout << "-- key polynomials --" << endl;

	cout << "f:  " << f.pol_to_string(12) << endl;
	cout << "fp: " << fp.pol_to_string(12) << endl;
	cout << "fq: " << fq.pol_to_string(12) << endl;
	cout << "g:  " << g.pol_to_string(12) << endl;
	cout << "h:  " << h.pol_to_string(12) << endl << endl;

	cout << "-- encryption testing --" << endl;

	string msg = "some test data to encrypt";
	cout << "data: " << msg << endl;


	vector<Polynomial> poly_msg = str_to_polyv(msg, deg);
	cout << "polynomial representation: " << poly_msg[0].pol_to_string(12) << endl;

	vector<Polynomial> enc = ntru_encrypt(poly_msg, h, q, d);

	cout << "encrypted: " << enc[0].pol_to_string(12) << endl;

	enc = ntru_decrypt(enc, f, fp, q, p);

	msg = polyv_to_str(enc, deg);
	cout << "decrypted: " << enc[0].pol_to_string(12) << endl;

	BYTE hash[SHA256_BLOCK_SIZE];

	unsigned char* encoded = padding_encode(msg, hash);

	cout << "encoded: ";
		for (int i = 0; i < 128; i++)
	 	cout << hex << setw(2) << setfill('0') << (int)encoded[i];
	cout << endl;

	Polynomial encoded_poly = data_to_poly(encoded, 128, deg);
	Polynomial blind_poly = hash_to_poly(hash, 32, deg);
	delete[] encoded;

	cout << "s || t:  " << encoded_poly.pol_to_string(12) << endl;
	cout << "H(M||R): " << blind_poly.pol_to_string(48) << endl;

	Polynomial encrypted = (encoded_poly + blind_poly * h) % q;
	for (int i = 0; i < deg; i++)
		encrypted[i] += q;
	encrypted = encrypted % q;
	cout << "Encrypted: " << encrypted.pol_to_string(12) << endl;

	Polynomial decrypted = (encrypted * f) % q;
	decrypted = minimize(decrypted, q);
	decrypted = decrypted % p;
	decrypted = decrypted * fp % p;
	decrypted = minimize(decrypted, p);
	cout << "Decrypted: " << decrypted.pol_to_string(12) << endl;

	encoded = poly_to_data(decrypted, 128, deg);

	string data = padding_decode(encoded);
	cout << "decoded: " << data << endl;
	delete[] encoded; // */

	/* // benchmark
	// benchmark("NTRU Key generation", 100, test_operation);
	int iterations = 1000;
	string name = "NTRU-OAEP Decryption";

	vector<Polynomial> key = generate_ntru_key(deg, p, q, d);

	Polynomial f = key[0], g = key[1], fp = key[2], fq = key[3];
	Polynomial h = p * fq * g % q;
	string data = "The quick brown fox jumps over the lazy dog while exploring a vast forest full of little secrets";
	BYTE hash[SHA256_BLOCK_SIZE];
	unsigned char* encoded = padding_encode(data, hash);
	Polynomial encoded_poly = data_to_poly(encoded, 128, deg);
	Polynomial blind_poly = hash_to_poly(hash, 32, deg);
	delete[] encoded;

	Polynomial encrypted = (encoded_poly + blind_poly * h) % q;

	using namespace chrono;

    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        Polynomial decrypted = (encrypted * f) % q;
		decrypted = minimize(decrypted, q);
		decrypted = decrypted % p;
		decrypted = minimize(decrypted, p);
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();

    std::cout << name << ": (" << iterations << " iterations)\n";
    std::cout << "  Total time: " << duration << " μs\n";
    std::cout << "  Avg per op: " << (double)duration / iterations << " μs\n\n"; // */
}

void test_operation() {
	int p = 3;
	int q = 4096;
	int deg = 821;
	int d = 320;

	string data = "The quick brown fox jumps over the lazy dog while exploring a vast forest full of little secrets";

    vector<Polynomial> key = generate_ntru_key(deg, p, q, d);

	Polynomial f = key[0], g = key[1], fp = key[2], fq = key[3];
	Polynomial h = p * fq * g % q;
}

void benchmark(const string& name, int iterations, void (*func)()) {
    using namespace chrono;

    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        func();
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();

    std::cout << name << ": (" << iterations << " iterations)\n";
    std::cout << "  Total time: " << duration << " μs\n";
    std::cout << "  Avg per op: " << (double)duration / iterations << " μs\n\n";
}


template <size_t len>
Polynomial::Polynomial(const int (&arr)[len]) :deg(len)
{
	if (len == 0 || !arr)
	{
		pol = NULL;
		return;
	}

	pol = new int[deg];
	if (!pol)
	{
		deg = 0;
		pol = NULL;
		return;
	}

	for (int i = 0; i < deg; i++)
		pol[i] = arr[i];
}

Polynomial::Polynomial(const int* arr, int len) :deg(len)
{
	if (deg == 0)
	{
		pol = NULL;
		return;
	}

	pol = new int[deg];
	if (!pol)
	{
		pol = NULL;
		deg = 0;
		return;
	}

	for (int i = 0; i < deg; i++)
		pol[i] = arr[i];
}

Polynomial::Polynomial(int len) :deg(len)
{
	if (len == 0)
	{
		pol = NULL;
		return;
	}

	pol = new int[deg];
	if (!pol)
	{
		deg = 0;
		pol = NULL;
		return;
	}

	for (int i = 0; i < deg; i++)
		pol[i] = 0;
}

Polynomial::Polynomial(const Polynomial& other)
{
	deg = other.deg;
	pol = new int[deg];
	for (int i = 0; i < deg; i++)
		pol[i] = other.pol[i];
}

Polynomial::~Polynomial()
{
	if (pol)
		delete[] pol;
}

string Polynomial::pol_to_string(int max_deg)
{
	int out_deg;
	if (max_deg <= 0)
		out_deg = deg;
	else if (max_deg < deg)
		out_deg = max_deg;
	else
	{
		cerr << "invalid max_deg value" << endl;
		return "";
	}

	string st = "";
	bool first = true;

	for (int i = 0; i < out_deg; i++)
	{
		int c = pol[i];
		if (c == 0) continue;

		if (!first)
		{
			st = st + (c > 0 ? " + " : " - ");
		}
		else 
		{
			if (c < 0) 
				st = st + "-";
		}

		int abs_c = abs(c);
		if (abs_c != 1 || i == 0) 
			st = st + to_string(abs_c);
		if (i >= 1) 
			st = st + "x";
		if (i >= 2) 
			st = st + "^" + to_string(i);

		first = false;
	}

	if (first) return "0";
	return st;
}

ostream& operator<<(ostream& os, const Polynomial& poly)
{
	string st = "";
	bool first = true;

	for (int i = 0; i < poly.deg; i++)
	{
		int c = poly.pol[i];
		if (c == 0) continue;

		if (!first)
		{
			st = st + (c > 0 ? " + " : " - ");
		}
		else 
		{
			if (c < 0) 
				st = st + "-";
		}

		int abs_c = abs(c);
		if (abs_c != 1 || i == 0) 
			st = st + to_string(abs_c);
		if (i >= 1) 
			st = st + "x";
		if (i >= 2) 
			st = st + "^" + to_string(i);

		first = false;
	}
	
	if (first) os << "0";
	else
		os << st;

	return os;
}

Polynomial& Polynomial::operator=(const Polynomial& oth)
{
	if (&oth != this)
	{
		if (pol)
			delete[] pol;

		deg = oth.deg;
		pol = new int[deg];

		for (int i = 0; i < deg; i++)
			pol[i] = oth.pol[i];
	}
	return *this;
}

int& Polynomial::operator[](int ind)
{
	if (ind >= 0 && ind < deg)
		return pol[ind];
	else
		throw out_of_range("Index is out of bounds");
}

Polynomial operator*(const Polynomial& pol1, const Polynomial& pol2)
{
	if (pol1.deg != pol2.deg)
		return pol1;
	else
	{
		int deg = pol1.deg;
		Polynomial res(deg);

		for (int i = 0; i < deg; i++)
			for (int j = 0; j < deg; j++)
				res.pol[(i + j) % deg] += pol1.pol[i] * pol2.pol[j];

		return res;
	}
}

Polynomial operator*(const Polynomial& pol, int ml)
{
	int deg = pol.deg;
	Polynomial res(deg);

	for (int i = 0; i < deg; i++)
		res.pol[i] = pol.pol[i] * ml;

	return res;
}

Polynomial operator*(int ml, const Polynomial& pol)
{
	int deg = pol.deg;
	Polynomial res(deg);

	for (int i = 0; i < deg; i++)
		res.pol[i] = pol.pol[i] * ml;

	return res;
}

Polynomial operator+(const Polynomial& pol1, const Polynomial& pol2)
{
	if (pol1.deg != pol2.deg)
		return pol1;
	else
	{
		int deg = pol1.deg;
		Polynomial res(deg);

		for (int i = 0; i < deg; i++)
			res.pol[i] = pol1.pol[i] + pol2.pol[i];

		return res;
	}
}

Polynomial operator-(const Polynomial& pol1, const Polynomial& pol2)
{
	if (pol1.deg != pol2.deg)
		return pol1;
	else
	{
		int deg = pol1.deg;
		Polynomial res(deg);

		for (int i = 0; i < deg; i++)
			res.pol[i] = pol1.pol[i] - pol2.pol[i];

		return res;
	}
}

Polynomial operator%(const Polynomial& pol, int mod)
{
	if (mod <= 0)
		return pol;

	int deg = pol.deg;
	Polynomial res(deg);

	for (int i = 0; i < deg; i++)
		res.pol[i] = pol.pol[i] % mod;

	return res;
}

int inverse_integer(int num, int mod)
{
	int r0 = mod;
	int r1;
	if (num < 0)
		r1 = num - mod * (num / mod) + mod;
	else
		r1 = num;

	int s0 = 0;
	int s1 = 1;

	int q;
	int tmp;

	while (r1 != 0)
	{
		q = r0 / r1;

		tmp = r1;
		r1 = r0 - r1 * q;
		r0 = tmp;

		tmp = s1;
		s1 = s0 - s1 * q;
		s0 = tmp;
	}
	
	if (r0 > 1) return 0;
	if (s0 < 0) s0 += mod;
	return s0;
}

Polynomial mod_div(const Polynomial& pol1, const Polynomial& pol2, int mod)
{
	int deg = pol1.deg;
	Polynomial res(deg);
	Polynomial div = pol1;

	int deg1 = deg - 1;
	int deg2 = deg - 1;

	while (deg2 >= 0 && pol2.pol[deg2] == 0) --deg2;
	while (deg1 >= deg2 && pol1.pol[deg1] == 0) --deg1;

	while (deg1 >= deg2)
	{
		int div_res = inverse_integer(pol2.pol[deg2], mod);
		if (!div_res)
			return Polynomial(0);
		int coef = div[deg1] * div_res % mod;
		int shift = deg1 - deg2;
		res[shift] = coef;

		Polynomial xn(deg);
		xn[shift] = 1;

		div = (div - xn * pol2 * coef) % mod;
		while (deg1 >= 0 && div[deg1] == 0) --deg1;
	}

	return res % mod;
}

bool check_zero(const Polynomial poly)
{
	for (int i = 0; i < poly.deg; i++)
		if (poly.pol[i] != 0)
			return true;

	return false;
}

bool check_one(const Polynomial poly)
{
	if (poly.pol[0] != 1)
		return false;

	for (int i = 1; i < poly.deg; i++)
		if (poly.pol[i] != 0)
			return false;

	return true;
}

int eucl_inverse_mod(Polynomial pol, int mod, Polynomial *inv)
{
	Polynomial q;
	Polynomial tmp;
	int deg = pol.deg;

	Polynomial r0(deg + 1);
	r0[0] = -1;
	r0[deg] = 1;

	Polynomial r1(deg + 1);
	for (int i = 0; i < deg + 1; i++)
	{
		if (i < deg)
			r1[i] = pol[i];
	}
	// cout << r0 << endl;
	// cout << r1 << endl;

	Polynomial t0(deg + 1);
	Polynomial t1(deg + 1);
	t1[0] = 1;

	while(check_zero(r1))
	{
		q = mod_div(r0, r1, mod);
		if (!q.deg)
			return 1;
		q = q % mod;

		// cout << "q: " << q << endl;
		
		tmp = r1;
		r1 = (r0 - r1 * q) % mod;
		r0 = tmp;
		
		// cout << "r: " << r1 << endl;

		tmp = t1;
		t1 = (t0 - t1 * q) % mod;
		t0 = tmp;
	}

	if (r0[0] < 0)
		r0[0] = r0[0] + mod;

	if (!check_one(r0)) return 1;

	*inv = Polynomial(deg);

	for (int i = 0; i < deg; i++)
		inv->pol[i] = t0[i];
	
	return 0;
}

int eucl_inverse_mod2k(Polynomial pol, int mod, Polynomial *inv)
{
	int deg = pol.deg;
	int md2k = mod;
	while(md2k > 2)
	{
		if (md2k % 2 != 0)
		{
			cout << "Modulus must be the power of 2" << endl;
			return 1;
		}
		md2k /= 2;
	}

	Polynomial res;
	int ret = eucl_inverse_mod(pol, 2, &res);

	if (ret)
		return 1;

	Polynomial int_2(deg);
	int_2[0] = 2;

	while (md2k < mod)
	{
		md2k *= 2;
		res = res * (int_2 - pol * res) % md2k;
	}

	*inv = res;
	return 0;
}

Polynomial generate_ternary_poly(int deg, int d)
{
	Polynomial res(deg);

	vector<int> inds(deg);
	iota(inds.begin(), inds.end(), 0);

	for (int i = deg - 1; i > 0; --i) 
	{
        uint32_t j;
        randombytes_buf(&j, sizeof(j));
        j = j % (1 + i);
        swap(inds[i], inds[j]);
    }

	for (int i = 0; i < d; i++)
		res[inds[i]] = 1;
	for (int i = 0; i < d; i++)
		res[inds[i + d]] = -1;

	return res;
}

vector<Polynomial> generate_ntru_key(int deg, int p, int q, int d)
{
	Polynomial f(deg);
	f[0] = 1;

	Polynomial gen = generate_ternary_poly(deg - 1, d);

	Polynomial g(deg);
	for (int i = 0; i < deg - 1; i++)
		g[i] = gen[i];

	Polynomial fq;
	Polynomial fp;

	while(true)
	{
		gen = generate_ternary_poly(deg - 1, d);
		for (int i = 0; i < deg - 1; i++)
			f[i] = f[i] + 3 * gen[i];

		int ret = eucl_inverse_mod2k(f % q, q, &fq);
		if (ret)
			continue;
	
		ret = eucl_inverse_mod(f % p, p, &fp);
		if (ret)
			continue;

		break;
	}
	vector<Polynomial> key = {f, g, fp, fq};
	return key;
}

vector<Polynomial> str_to_polyv(const string& msg, int deg)
{
	int poly_chs = deg / 6;
	int poly_len;
	if (msg.length() % poly_chs == 0)
		poly_len = msg.length() / poly_chs;
	else
		poly_len = msg.length() / poly_chs + 1;

	vector<Polynomial> poly_msg(poly_len);

	for (int i = 0; i < poly_len; i++)
	{
		Polynomial ch_poly(deg);

		for (int j = 0; j < poly_chs; j++)
		{
			unsigned char c;
			if (i * poly_chs + j < msg.length())
				c = msg[i * poly_chs + j];
			else if (i * poly_chs + j == msg.length())
				c = 1;
			else
				break;

			int k = 5;
			while (c > 0)
			{
				int coef = c % 3;
				coef = (coef == 2) ? -1 : coef;

				ch_poly[j * 6 + k] = coef;
				k--;
				c /= 3;
			}
		}

		poly_msg[i] = ch_poly;
	}
	return poly_msg;
}

Polynomial data_to_poly(const unsigned char* msg, int len, int deg)
{
	int poly_chs = deg / 6;

	Polynomial poly_data(deg);

	for (int j = 0; j < poly_chs; j++)
	{
		unsigned char c;
		if (j < len)
			c = msg[j];
		else if (j == len)
			c = 1;
		else
			break;

		int k = 5;
		while (c > 0)
		{
			int coef = c % 3;
			coef = (coef == 2) ? -1 : coef;

			poly_data[j * 6 + k] = coef;
			k--;
			c /= 3;
		}
	}

	return poly_data;
}

Polynomial hash_to_poly(const unsigned char* msg, int len, int deg)
{
	int poly_chs = deg / 6;

	Polynomial poly_data(deg);

	for (int j = 0; j < poly_chs; j++)
	{
		unsigned char c;
		if (j < len)
			c = msg[j];
		else if (j == len)
			c = 1;
		else
			break;

		int k = 5;
		while (c > 0)
		{
			int coef = c % 3;
			coef = (coef == 2) ? -1 : coef;

			poly_data[j * 24 + k * 4] = coef;
			k--;
			c /= 3;
		}
	}

	return poly_data;
}

unsigned char* poly_to_data(Polynomial poly, int len, int deg)
{
	unsigned char* data = new unsigned char[len];
	int poly_chs = deg / 6;

	for (int i = 0; i < poly_chs; i++)
	{
		unsigned char c = 0;

		for (int j = 0; j < 6; j++)
		{
			c *= 3;
			int coef = poly[i * 6 + j];
			coef = (coef == -1) ? 2 : coef;

			c += coef;
		}

		if (i < len)
			data[i] = c;
	}
	return data;
}

string polyv_to_str(const vector<Polynomial> poly_msg, int deg)
{
	int poly_chs = deg / 6;
	int str_len = poly_msg.size() * poly_chs * 6;

	string data = "";

	for (int i = 0; i < poly_msg.size(); i++)
	{
		Polynomial ch_poly = poly_msg[i];

		for (int j = 0; j < poly_chs; j++)
		{
			unsigned char c = 0;

			for (int k = 0; k < 6; k++)
			{
				c *= 3;
				int coef = ch_poly[j * 6 + k];
				coef = (coef == -1) ? 2 : coef;

				c += coef;
			}

			if (c && c != 1)
				data = data + (char)c;
		}
	}

	return data;
}

Polynomial random_blind(int deg)
{
	Polynomial res(deg);

	for (int i = 0; i < deg; i++)
	{
		uint8_t r = randombytes_uniform(3);
		res[i] = static_cast<int>(r) - 1;
	}

	return res;
}

vector<Polynomial> ntru_encrypt(vector<Polynomial> data, Polynomial pub_key, int q, int dr)
{
	int deg = pub_key.deg;
	Polynomial blind;
	vector<Polynomial> enc_data(data.size());

	for (int i = 0; i < data.size(); i++)
	{
		blind = generate_ternary_poly(deg, dr);
		enc_data[i] = (blind * pub_key + data[i]) % q;
	}

	return enc_data;
}

Polynomial minimize(Polynomial poly, int mod)
{
	int deg = poly.deg;
	Polynomial res(deg);

	for (int i = 0; i < deg; i++)
	{
		if (poly[i] > (mod - mod % 2) / 2 - (mod + 1) % 2)
			res[i] = poly[i] - mod;
		else if (poly[i] < -(mod - mod % 2) / 2)
			res[i] = poly[i] + mod;
		else
			res[i] = poly[i];
	}
	return res;
}

vector<Polynomial> ntru_decrypt(vector<Polynomial> enc_data, Polynomial priv_f, Polynomial priv_fp, int q, int p)
{
	vector<Polynomial> data(enc_data.size());

	for (int i = 0; i < enc_data.size(); i++)
	{
		Polynomial block = priv_f * enc_data[i] % q;
		block = minimize(block, q);

		block = block % p;
		block = priv_fp * block % p;

		block = minimize(block, p);
		data[i] = block;
	}
	return data;
}

unsigned char* I20SP (unsigned int x, int len)
{
	unsigned char* res = new unsigned char[len];

	for (int i = 0; i < len; i++)
	{
		res[3 - i] = x & 0xff;
		x >>= 8;
	}
	return res;
}

// mask generating function
unsigned char* mgf1(unsigned char* seed, int seedLen, int maskLen) 
{
	unsigned char* mask = new unsigned char[maskLen];

	unsigned char* seed_ctr = new unsigned char[seedLen + 4];
	for (int i = 0; i < seedLen; i++)
		seed_ctr[i] = seed[i];
	
	int iter;
	if (maskLen % SHA256_BLOCK_SIZE == 0)
		iter = maskLen / SHA256_BLOCK_SIZE;
	else 
		iter = maskLen / SHA256_BLOCK_SIZE + 1;

	for (unsigned int i = 0; i < iter; i++)
	{
		unsigned char* ctrStr = I20SP(i, 4);
		
		BYTE hash[SHA256_BLOCK_SIZE];
		for (int j = 0; j < 4; j++)
			seed_ctr[seedLen + j] = ctrStr[j];
		sha256((const BYTE*)seed_ctr, seedLen + 4, hash);

		for (int j = 0; j < SHA256_BLOCK_SIZE; j++)
		{
			if (i * SHA256_BLOCK_SIZE + j < maskLen)
				mask[i * SHA256_BLOCK_SIZE + j] = hash[j];
			else 
				break;
		}
		delete[] ctrStr;
	}
	delete[] seed_ctr;

	return mask;
}

unsigned char* padding_encode(string data, unsigned char* hash)
{
	unsigned char* enc_data = new unsigned char[129];

	unsigned char* rand = new unsigned char[32];
	randombytes_buf(rand, 32);

	unsigned char* mask = mgf1(rand, 32, 96);

	for (int i = 0; i < 96; i++)
	{
		if (i < data.size())
			enc_data[i] = data[i] ^ mask[i];
		else if (i == data.size())
			enc_data[i] = 0x01 ^ mask[i];
		else
			enc_data[i] = mask[i];
	}
	delete[] mask;

	mask = mgf1(enc_data, 96, 32);
	for (int i = 0; i < 32; i++)
		enc_data[96 + i] = rand[i] ^ mask[i];
	delete[] mask;

	enc_data[128] = '\0';

	BYTE m_r_string[128];
	for (int i = 0; i < 96; i++)
	{
		if (i < data.size())
			m_r_string[i] = data[i];
		else if (i == data.size())
			m_r_string[i] = 0x01;
		else
			m_r_string[i] = 0x00;
	}

	for (int i = 96; i < 128; i++)
		m_r_string[i] = rand[i % 32];

	delete[] rand;
	sha256(m_r_string, 128, hash);

	return enc_data;
}

string padding_decode(unsigned char* enc_data)
{
	unsigned char* mask = mgf1(enc_data, 96, 32);
	for (int i = 0; i < 32; i++)
		enc_data[96 + i] = enc_data[96 + i] ^ mask[i];
	delete[] mask;

	mask = mgf1(enc_data + 96, 32, 96);

	for (int i = 0; i < 96; i++)
		enc_data[i] = enc_data[i] ^ mask[i];
	delete[] mask;

	int len = 0;
	while(enc_data[len] && len < 96) len++;

	string data = "";
	for (int i = 0; i < len; i++)
		data += enc_data[i];
	data += '\0';

	return data;
}