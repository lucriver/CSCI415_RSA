/* RSA class definition */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <sstream>
#include <map>

#include "BigInt.cpp"

// info: this class allows for the implementation of an RSA crypto-system
class RSA {
  static const int MIN_DIGITS = 3;                 // Minimum number of digits for RSA primes
  static const int MAX_DIGITS = 200;                // Max number of digits for RSA primes
  static const int BLOCK_SIZE_PLAINTEXT_BYTES = 3;
  static const int BLOCK_SIZE_CIPHERTEXT_BYTES = 4;

public:

  // Initialize RSA crypto-system
  RSA(const int);
  ~RSA();

  BigInt getPublicKey() const;
  BigInt getPrivateKey() const;
  BigInt getKeyModulo() const;

  // TODO- these need to be worked on
  std::string encrypt(const std::string&);
  std::string decrypt(const std::string&);

  // ---- debugging function, outputs all class member values
  void debug();

private:
  struct Codebook {
    Codebook():
      char_num({
        {'A', 0}, {'B', 1}, {'C', 2}, {'D', 3}, {'E', 4},
        {'F', 5}, {'G', 6}, {'H', 7}, {'I', 8}, {'J', 9},
        {'K', 10}, {'L', 11}, {'M', 12}, {'N', 13}, {'O', 14},
        {'P', 15}, {'Q', 16}, {'R', 17}, {'S', 18}, {'T', 19},
        {'U', 20}, {'V', 21}, {'W', 22}, {'X', 23}, {'Y', 24}, {'Z', 25}
        }),
      num_char({
        {0, 'A'}, {1, 'B'}, {2, 'C'}, {3, 'D'}, {4, 'E'},
        {5, 'F'}, {6, 'G'}, {7, 'H'}, {8, 'I'}, {9, 'J'},
        {10, 'K'}, {11, 'L'}, {12, 'M'}, {13, 'N'}, {14, 'O'},
        {15, 'P'}, {16, 'Q'}, {17, 'R'}, {18, 'S'}, {19, 'T'},
        {20, 'U'}, {21, 'V'}, {22, 'W'}, {23, 'X'}, {24, 'Y'}, {25, 'Z'}
        }) {
    }
    std::map<char, BigInt> char_num;
    std::map<BigInt, char> num_char;
    bool check_char(std::map<char, BigInt> map, char key) { if (map.find(key) == map.end()) { return false; } else { return true; } };
    bool check_num(std::map<BigInt, char> map, BigInt key) { if (map.find(key) == map.end()) { return false; } else { return true; } };
    BigInt char_to_num(const char& c) { try { return char_num.at(c); } catch (std::exception& ex) { throw ex; } }
    char num_to_char(const BigInt& x) { try { return num_char.at(x); } catch (std::exception& ex) { throw ex; } }
  };
  Codebook codebook;

  BigInt p, q; // primes p and q
  BigInt n;    // modulo used with keys
  BigInt phi_n;
  BigInt e;    // public key
  BigInt d;    // private key

  std::string encrypt_plaintext_block(const std::string&, Codebook*);
  std::string decrypt_ciphertext_block(const std::string&, Codebook*);
  BigInt generateRandomPrime(const int) const;
  BigInt randomBigInt(const int) const;
  BigInt randomBigIntInRange(const BigInt, const BigInt) const;
  BigInt fastModExpBigInt(BigInt, BigInt, BigInt) const;
  BigInt euclidsExtended(BigInt, BigInt) const;
  BigInt pow(const BigInt&, int) const;
  long long fastModExp(long long, long long, long long) const;
  bool isPrimeMRT(const BigInt, const int) const;
  bool MRT(BigInt, const BigInt) const;
};


// ---- debugging function, use it when needed. don't forget to delete
inline
void RSA::debug() {
  std::cout << "********** RSA SYSTEM VALUES **********" << std::endl;
  std::cout << "{"
    << "'p': " << p << "," << std::endl
    << "'q': " << q << "," << std::endl
    << "'n': " << getKeyModulo() << "," << std::endl
    << "'phi_n': " << phi_n << "," << std::endl
    << "'e': " << getPublicKey() << "," << std::endl
    << "'d': " << getPrivateKey() << "," << std::endl
    << "}"
    << std::endl;
  std::cout << "***************************************" << std::endl;
}


// ******************** Public methods ********************

// info: Initializes the RSA class so that encryption and decryption can occur.
// params: int specifying how many digits the primes used for the RSA scheme should be
// returns: RSA class members are assigned values such that encryption and decryption can take place.
inline
RSA::RSA(const int decimal_digits_count) {
  std::cout << "Initializing RSA crypto-system..." << std::endl;
  // verify number of digits for primes p and q are valid
  if (decimal_digits_count < MIN_DIGITS || decimal_digits_count > MAX_DIGITS) {
    const std::string s = "Invalid number of decimal digits. " + std::to_string(MIN_DIGITS) + " <= x <= " + std::to_string(MAX_DIGITS);
    throw std::invalid_argument(s);
  }

  // calculate random primes p and q of lenght decimal_digits_count
  std::cout << "Initializing system primes..." << std::endl;
  while (1) {
    p = generateRandomPrime(decimal_digits_count);
    q = generateRandomPrime(decimal_digits_count);
    if (p != q) {
      break;
    }
  }
  std::cout << "System primes initialized." << std::endl;

  n = BigInt((p * q));                                // calculate n
  phi_n = BigInt((p - BigInt(1)) * (q - BigInt(1)));  // calcualte phi_n

  std::cout << "Calculating system keys..." << std::endl;
  for (BigInt i = 2; i < phi_n; i = i + 1) { // calculate public key e such that gcd(phi_n,e) = 1 for 1 < e < phi_n
    if (gcd(i, phi_n) == 1) {
      e = i;
      break;
    }
  }
  if (e <= BigInt(1) || e >= phi_n)         // sanity check- this condition should never be true
    throw std::logic_error("Calculated euler totient is of incorrect value. Try again");

  d = euclidsExtended(e, phi_n);            // calculate private key d
  if (((e * d) % phi_n) != BigInt(1))      // another sanity check- this condition should never be true
    throw std::logic_error("Variables produced violate requirements for RSA. Try again");

  std::cout << "System keys initialized." << std::endl;

  std::cout << "RSA crypto-system initialized." << std::endl;

  codebook.char_num.insert({ 'a',BigInt(23) });
}

inline
RSA::~RSA() {}

// info: returns the public key for the RSA crypto-system
inline
BigInt RSA::getPublicKey() const {
  return e;
}

// info: returns the private key for the RSA crypto-system
inline
BigInt RSA::getPrivateKey() const {
  return d;
}

// info: returns the modulo n to use with the public and private keys
inline
BigInt RSA::getKeyModulo() const {
  return n;
}

// TODO
inline
std::string RSA::encrypt(const std::string& s) {
  Codebook* cbook_ptr;
  cbook_ptr = &codebook;
  return encrypt_plaintext_block(s, cbook_ptr);
}

// TODO 
inline
std::string RSA::decrypt(const std::string& s) {
  Codebook* cbook_ptr;
  cbook_ptr = &codebook;
  return decrypt_ciphertext_block(s, cbook_ptr);
}

// ****************************************


// ******************** Private methods ********************

inline
std::string RSA::encrypt_plaintext_block(const std::string& block, Codebook* codebook) {

  BigInt trigraph = 0;
  for (int i = 0; i < BLOCK_SIZE_PLAINTEXT_BYTES; i++) {
    if (!codebook->check_char(codebook->char_num,toupper(char(block[i])))) {
      throw std::range_error("Unreadable plaintext character detected. Ensure plaintext consists of ONLY LETTERS.");
    }
    trigraph += pow(26, (BLOCK_SIZE_PLAINTEXT_BYTES - 1) - i) * codebook->char_to_num(toupper((char(block[i]))));
  }

  BigInt ciphertext = fastModExpBigInt(trigraph, e, n);

  BigInt code_0 = ciphertext / pow(26, 3);
  ciphertext = ciphertext % pow(26, 3);

  BigInt code_1 = ciphertext / pow(26, 2);
  ciphertext = ciphertext % pow(26, 2);

  BigInt code_2 = ciphertext / 26;
  BigInt code_3 = ciphertext % 26;

  const BigInt codes[BLOCK_SIZE_CIPHERTEXT_BYTES] = { code_0,code_1,code_2,code_3 };

  std::string quadragraph = "";

  srand(time(0));
  for (int i = 0; i < BLOCK_SIZE_CIPHERTEXT_BYTES; i++) {
    if (!codebook->check_num(codebook->num_char, codes[i])) {
      char new_char = char((rand() % 26) + 97);
      int counter = 0;
      while (codebook->check_char(codebook->char_num,new_char)) {
        if (counter >= 100) {
          throw std::logic_error("Failure to assign new key value for trigraph code.");
        }
        new_char = char((rand() % 26) + 97);
        counter++;
      }
      codebook->char_num.insert({ new_char,codes[i] });
      quadragraph += new_char;
      continue;
    }
    quadragraph += char(codes[i].longValue() + 65);
  }

  return quadragraph;
}


inline
std::string RSA::decrypt_ciphertext_block(const std::string& block, Codebook* codebook) {

  BigInt ciphertext(0);
  for (int i = 0; i < BLOCK_SIZE_CIPHERTEXT_BYTES; i++) {
    ciphertext += BigInt(codebook->char_to_num(char(block[i]))) * pow(26, (BLOCK_SIZE_CIPHERTEXT_BYTES - 1 - i));
  }

  BigInt trigraph = fastModExpBigInt(ciphertext, d, n);

  BigInt num_0 = trigraph / pow(26, 2);

  trigraph = trigraph % pow(26, 2);

  BigInt num_1 = trigraph / 26;
  BigInt num_2 = trigraph % 26;

  std::string plaintext_string = "";

  plaintext_string += codebook->num_to_char(num_0);
  plaintext_string += codebook->num_to_char(num_1);
  plaintext_string += codebook->num_to_char(num_2);

  return plaintext_string;
}

// info: Get an n-digit random prime number that has been verified via the miller-rabin method.
// params: int specifying how many digits prime should be
// returns: a random n-digit miller-rabin prime of BigInt type
inline
BigInt RSA::generateRandomPrime(const int decimal_digits_count) const {
  std::random_device rd;      // generate seed for random number generator (rng)
  std::mt19937_64 rng(rd());  // random number generator

  // used to generate a seq. of uniformly distributed random digits between 0-9
  std::uniform_int_distribution<int> dist(0, 9);

  // create a "decimal_digits"-digits random number
  std::string rand_num = "1";
  for (int i = 0; i < decimal_digits_count - 2; i++) {
    std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
    rand_num += rand_digit;                             // append to random_number
  }
  rand_num += "1";

  // use miller-rabin to determine if rand_num is prime
  std::cout << "Looking for primes..." << std::endl;
  int counter = 0;
  const int reset_interval = 200; // when counter == reset_interval, stop shuffling and make new prime candidate
  const int max_evals = 5000;     // max number of prime candidates to check
  const int rounds = 40;          // number of rounds for miller-rabin algorithm
  while (!isPrimeMRT(BigInt(rand_num), rounds)) { // while prime candidate is not prime by miller-rabin method
    counter++;
    std::cout << "Prime candidates evaluated: " << counter;
    if (counter % reset_interval == 0) {        // if we have checked another 200 prime candidates
      if (counter == max_evals) {               // if we have evaluated too many potential primes, throw exception
        throw std::runtime_error("Timeout on prime number generation. Please try again.");
      }
      else {                                    // create a completely new prime candidate
        for (int i = 1; i < decimal_digits_count - 1; i++) {
          std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
          rand_num[i] = rand_digit[0];
        }
      }
    }
    else {                                      // if we have not checked another 200 prime candidates
      // shuffle every digit of the prime candidate, except first and last digit
      std::shuffle(rand_num.begin() + 1, rand_num.end() - 1, rng);
    }
    std::cout << "\r";
  }
  std::cout << std::endl << "Prime acquired." << std::endl;

  return BigInt(rand_num);
}

// info: return true or false if BigInt n is prime based on miller-rabin test.
// params: prime candidate BigInt and number of rounds for miller-rabin test.
inline
bool RSA::isPrimeMRT(const BigInt num, const int rounds) const {
  if (num != BigInt(2) && num.isEven()) {
    return false;
  }
  if (num <= BigInt(1) || num == BigInt(4)) {
    return false;
  }
  if (num < BigInt(4)) {
    return true;
  }
  BigInt x = num - BigInt(1);
  while (x.isEven()) {
    x = x / BigInt(2);
  }
  for (int i = 0; i < rounds; i++) {
    if (!MRT(x, num)) {
      return false;
    }
  }
  return true;
}

// info: simple helper function for the isPrimeMRT method.
inline
bool RSA::MRT(BigInt x, const BigInt num) const {
  BigInt a = randomBigIntInRange(BigInt(2), num - BigInt(1));
  BigInt z = fastModExpBigInt(a, x, num);

  if (z == BigInt(1) || z == num - BigInt(1)) {
    return true;
  }

  while (x != num - BigInt(1)) {
    z = (z * z) % num;
    x = x * BigInt(2);

    if (z == BigInt(1)) {
      return false;
    }
    if (z == num - BigInt(1)) {
      return true;
    }
  }

  return false;
}

// info: return a random, n-digit number of BigInt type
// params: number of digits the random number should have
inline
BigInt RSA::randomBigInt(const int digits_count) const {
  if (digits_count <= 0) {
    throw std::invalid_argument("Invalid number of digits for random number to be generated.");
  }

  std::stringstream ss;
  std::random_device rd;

  while (ss.tellp() < digits_count) { // while current random number is not enough digits in length
    ss << rd();                       // add new random number to the current random number
  }

  // convert current random number to string, truncate digits if number has too many digits
  std::string randomDigits = ss.str().substr(0, digits_count);
  return BigInt(randomDigits);
}

// info: return random number of BigInt type within specified range
// params: range of potential random number: (low <= rand <= high)
// returns: random number of big-int type whose value falls within low and high
inline
BigInt RSA::randomBigIntInRange(const BigInt low, const BigInt high) const {
  if (low >= high) {
    throw std::invalid_argument("Invalid value range for random number to be generated.");
  }

  BigInt diff = high - low;
  std::stringstream s;
  s << diff;
  BigInt rand_diff_range = randomBigInt(s.str().length() + 1);
  BigInt mod_r = rand_diff_range % diff;
  BigInt rand_val = low + mod_r;
  return rand_val;
}

inline
BigInt RSA::pow(const BigInt& base, int exp) const {
  if (exp < 0) {
    if (base == 0)
      throw std::logic_error("Cannot divide by zero");
    return base.abs() == 1 ? base : 0;
  }
  if (exp == 0) {
    if (base == 0)
      throw std::logic_error("Zero cannot be raised to zero");
    return 1;
  }

  BigInt result = base, result_odd = 1;
  while (exp > 1) {
    if (exp % 2)
      result_odd *= result;
    result *= result;
    exp /= 2;
  }

  return result * result_odd;
}

// info: implements the fast modular exponentiation algorithm in project requirements for BigInts
// params: BigInt's a, b and m
// returns: (a^b) mod (m)
inline
BigInt RSA::fastModExpBigInt(BigInt a, BigInt b, BigInt m) const {
  BigInt f(1);
  a = a % m;

  while (b > BigInt(0)) {     // Figure 9.8: for i = k until i = 0
    if (b.isOdd())            // Figure 9.8:  if b_i = 1 
      f = (f * a) % m;
    a = (a * a) % m;
    b = b / 2;                // Figure 9.8:  c <- 2 * c
  }

  return f;
}

// info: implements the fast modular exponentiation algorithm in project requirements
// params: long long's a, b and m
// returns: (a^b) mod (m)
inline
long long RSA::fastModExp(long long a, long long int b, long long m) const {
  long long f = 1;
  if (1 & b)
    f = a;
  while (1) {
    if (!b) break;
    b >>= 1;
    a = (a * a) % m;
    if (b & 1)
      f = (f * a) % m;
  }
  return f;
}

// info: extended euclidean algorithm, used for computing private key
inline
BigInt RSA::euclidsExtended(BigInt E, BigInt eulerTotient) const {
  BigInt a1 = 1, a2 = 0, b1 = 0, b2 = 1, d1 = eulerTotient, d2 = E, temp;

  while (d2 != 1) {
    BigInt k = (d1 / d2);

    temp = a2;
    a2 = a1 - (a2 * k);
    a1 = temp;

    temp = b2;
    b2 = b1 - (b2 * k);
    b1 = temp;

    temp = d2;
    d2 = d1 - (d2 * k);
    d1 = temp;
  }
  BigInt x = b2;

  if (x > eulerTotient) {
    x = x % eulerTotient;
  }
  else if (x < 0) {
    x = x + eulerTotient;
  }

  return x;
}

// ****************************************

