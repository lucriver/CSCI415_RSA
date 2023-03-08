/* RSA class definition */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <sstream>

#include "BigInt.cpp"

// info: this class allows for the implementation of an RSA crypto-system
class RSA {
  static const int MIN_DIGITS = 50; // Minimum number of digits for RSA primes
  static const int MAX_DIGITS = 200; // Max number of digits for RSA primes

public:

  // Initialize RSA crypto-system
  RSA(const int);
  ~RSA();

  BigInt getPublicKey() const;
  BigInt getPrivateKey() const;
  BigInt getKeyModulo() const;

  // TODO- these need to be worked on
  std::string encrypt(std::string) const;
  std::string decrypt(std::string) const;

  // ---- debugging function, outputs all class member values
  void debug();

private:
  BigInt p, q; // primes p and q
  BigInt n;    // modulo used with keys
  BigInt phi_n;
  BigInt e;    // public key
  BigInt d;    // private key
  BigInt generateRandomPrime(const int) const;
  BigInt randomBigInt(const int) const;
  BigInt randomBigIntInRange(const BigInt, const BigInt) const;
  BigInt fastModExpBigInt(BigInt, BigInt, BigInt) const;
  long long fastModExp(long long, long long, long long) const;
  BigInt euclidsExtended(BigInt, BigInt) const;
  bool isPrimeMRT(const BigInt, const int) const;
  bool MRT(BigInt, const BigInt) const;
};


// ---- debugging function, use it when needed. don't forget to delete
inline
void RSA::debug() {
  std::cout << "p: " << p << std::endl;
  std::cout << "q: " << q << std::endl;
  std::cout << "n: " << getKeyModulo() << std::endl;
  std::cout << "phi(n): " << phi_n << std::endl;
  std::cout << "e (public key): " << getPublicKey() << std::endl;
  std::cout << "d (private key): " << getPrivateKey() << std::endl;

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
  p = generateRandomPrime(decimal_digits_count);
  q = generateRandomPrime(decimal_digits_count);
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
  if (e <= BigInt(1) || e >= phi_n) {       // sanity check- this condition should never be true
    throw std::logic_error("Calculated euler totient is of incorrect value. Try again");
  }
  d = euclidsExtended(e, phi_n);            // calculate private key d
  if (((e * d) % phi_n) != BigInt(1)) {     // another sanity check- this condition should never be true
    throw std::logic_error("Variables produced violate requirements for RSA. Try again");
  }
  std::cout << "System keys initialized." << std::endl;

  std::cout << "RSA crypto-system initialized." << std::endl;
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
std::string RSA::encrypt(std::string m) const {
  BigInt plaintext(m);
  BigInt encoded_plaintext = fastModExpBigInt(plaintext, getPublicKey(), getKeyModulo());
  std::stringstream s;
  s << encoded_plaintext;
  std::string ciphertext = s.str();
  return ciphertext;
}

// TODO 
inline
std::string RSA::decrypt(std::string c) const {
  BigInt ciphertext(c);
  BigInt decoded_ciphertext = fastModExpBigInt(ciphertext, getPrivateKey(), getKeyModulo());
  std::stringstream s;
  s << decoded_ciphertext;
  std::string plaintext = s.str();
  return plaintext;
}

// ****************************************


// ******************** Private methods ********************

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

