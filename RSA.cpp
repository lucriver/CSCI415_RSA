/* RSA class definition */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <random>
#include <algorithm>

#include "BigInt.cpp"


// info: this class allows for the implementation of an RSA crypto-system
class RSA {
  static const int MIN_DIGITS = 100; // Minimum number of digits for RSA primes
  static const int MAX_DIGITS = 200; // Max number of digits for RSA primes

public:

  // Initialize RSA crypto-system
  RSA(const int);
  ~RSA();

private:
  BigInt p, q, n, modulo, pub_key, priv_key;

  BigInt generateRandomPrime(int);
  BigInt randomBigInt(int);
  BigInt randomBigIntInRange(BigInt, BigInt);
  BigInt binPow(BigInt, BigInt, BigInt);
  bool isPrimeMRT(BigInt, int);
  bool MRT(BigInt, BigInt);

};


// ******************** Public methods ********************

// info: Initializes the RSA class so that encryption and decryption can occur.
// params: int specifying how many digits the primes used for the RSA scheme should be
// returns: RSA class members are assigned values such that encryption and decryption can take place.
inline
RSA::RSA(const int decimal_digits_count) {
  std::cout << "Initializing RSA crypto-system." << std::endl;
  // verify number of digits for primes p and q are valid
  if (decimal_digits_count < MIN_DIGITS || decimal_digits_count > MAX_DIGITS) {
    std::string s = "Invalid number of decimal digits. " + std::to_string(MIN_DIGITS) + " <= x <= " + std::to_string(MAX_DIGITS);
    throw std::invalid_argument(s);
  }

  // define primes p and q that were verified with the miller-rabin method
  p = generateRandomPrime(decimal_digits_count);
  q = generateRandomPrime(decimal_digits_count);

  // define n
  n = BigInt(p * q);

  // define modulo (or alternatively phi(n) in textbook)
  modulo = BigInt((p - BigInt(1)) * (q - BigInt(1)));

  // define public key (or alternatively e in textbook)
  // define e

  // define private key (or alternatively d in textbook)
  // define d
}

inline
RSA::~RSA() {}

// ****************************************


// ******************** Private methods ********************

// info: Get an n-digit random prime number that has been verified via the miller-rabin method.
// params: int specifying how many digits prime should be
// returns: a random n-digit miller-rabin prime of BigInt type
inline
BigInt RSA::generateRandomPrime(int decimal_digits_count) {
  std::random_device rd;      // generate seed for random number generator (rng)
  std::mt19937_64 rng(rd());  // random number generator

  // usedd to generate a seq. of uniformly distributed random digits between 0-9
  std::uniform_int_distribution<int> dist(0, 9);

  // create a "decimal_digits"-digits random number
  std::string rand_num = "1";
  for (int i = 0; i < decimal_digits_count - 2; i++) {
    std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
    rand_num += rand_digit;                             // append to random_number
  }
  rand_num += "1";

  // use miller-rabin to determine if rand_num is prime
  std::cout << "Looking for primes." << std::endl;
  int rounds = 40;
  int counter = 0;
  int max_evals = 5000;
  while (!isPrimeMRT(BigInt(rand_num), rounds)) { // while prime candidate is not prime by miller-rabin method
    counter++;
    std::cout << "Prime candidates evaluated: " << counter;
    if (counter % 1000 == 0) {               
      if (counter == max_evals) {               // if we have evaluated too many potential primes, throw exception
        throw std::runtime_error("Timeout on prime number generation. Please try again.");
      } else {
        std::cout << std::endl << "Aborting shuffle and resetting prime candidate." << std::endl;
        for (int i = 1; i < decimal_digits_count - 1; i++) {
          std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
          rand_num[i] = rand_digit[0];
        }
        continue;
      }
    }
    // shuffle every digit of the prime candidate, except first and last digit
    std::shuffle(rand_num.begin() + 1, rand_num.end() - 1, rng);
    std::cout << "\r";
  }
  std::cout << std::endl << "Prime acquired." << std::endl;

  return BigInt(rand_num);
}

// info: return true or false if BigInt n is prime based on miller-rabin test.
// params: prime candidate BigInt and number of rounds for miller-rabin test.
inline
bool RSA::isPrimeMRT(BigInt n, int rounds) {
  if (n != BigInt(2) && n.isEven()) {
    return false;
  }
  if (n <= BigInt(1) || n == BigInt(4)) {
    return false;
  }
  if (n < BigInt(4)) {
    return true;
  }
  BigInt d = n - BigInt(1);
  while (d.isEven()) {
    d = d / BigInt(2);
  }
  for (int i = 0; i < rounds; i++) {
    if (!MRT(d, n)) {
      return false;
    }
  }
  return true;
}

// info: simple helper function for the isPrimeMRT method.
inline
bool RSA::MRT(BigInt d, BigInt n) {
  BigInt a = randomBigIntInRange(2, n - BigInt(1));
  BigInt x = binPow(a, d, n);

  if (x == BigInt(1) || x == n - BigInt(1)) {
    return true;
  }

  while (d != n - BigInt(1)) {
    x = (x * x) % n;
    d = d * BigInt(2);

    if (x == BigInt(1)) {
      return false;
    }
    if (x == n - BigInt(1)) {
      return true;
    }
  }

  return false;
}

// info: return a random, n-digit number of BigInt type
// params: number of digits the random number should have
inline
BigInt RSA::randomBigInt(int digits_count) {
  if (digits_count <= 0) {
    throw std::invalid_argument("Invalid number of digits for random number to be generated.");
  }

  std::stringstream ss;
  std::random_device rd;

  while (ss.tellp() < digits_count) {
    ss << rd();
  }

  std::string randomDigits = ss.str().substr(0, digits_count);
  return BigInt(randomDigits);
}

// info: return random number of BigInt type within specified range
// params: range of potential random number: (low <= rand <= high)
// returns: random number of big-int type whose value falls within low and high
inline
BigInt RSA::randomBigIntInRange(BigInt low, BigInt high) {
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

// info: helpful modular exponentiation function. allows us to compute (a ^ n) % m for numbers of BigInt type.
//  returns: (a ^ n) % m
inline
BigInt RSA::binPow(BigInt a, BigInt n, BigInt m) {
  BigInt res(1);
  a = a % m;

  while (n > BigInt(0)) {
    if (n.isOdd())
      res = (res * a) % m;
    a = (a * a) % m;
    n = n / 2;
  }

  return res;
}

// ****************************************

