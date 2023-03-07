/* RSA class definition */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <random>
#include <algorithm>

#include "BigInt.cpp"

class RSA {
  static const int MIN_DIGITS = 100;
  static const int MAX_DIGITS = 200;

  public:
    RSA();
    ~RSA();
    void generateRSA(const int);

    // ---
    void test();
    //--

  private:
    BigInt p, q;

    BigInt generateRandomPrime(int);
    BigInt randomBigInt(int);
    BigInt randomBigIntInRange(BigInt,BigInt);
    BigInt binPow(BigInt,BigInt,BigInt);
    bool isPrimeMRT(BigInt,int);
    bool MRT(BigInt,BigInt);

};

// -------------- Public methods --------------

// class methods will be defined outside the RSA class definition
// but within the RSA.cpp file, thus requiring "inline" keyword
inline 
RSA::RSA() { }

inline
RSA::~RSA() { }

inline
void RSA::generateRSA(const int decimal_digits_count) {
  // verify number of digits for primes p and q are valid
  if (decimal_digits_count < MIN_DIGITS || decimal_digits_count > MAX_DIGITS) {
    std::string s = "Invalid number of decimal digits. " + std::to_string(MIN_DIGITS) + " <= x <= " + std::to_string(MAX_DIGITS);
    throw std::invalid_argument(s);
  }

  // define RSA class member primes p and q that
  // were verified with the miller-rabin method
  p = generateRandomPrime(decimal_digits_count);
  q = generateRandomPrime(decimal_digits_count);
}


//---
inline
void RSA::test() {

}
// ---

// -------------- Private methods --------------

inline
BigInt RSA::generateRandomPrime(int decimal_digits_count) {
  std::random_device rd;    // generate seed for random number generator (rng)
  std::mt19937_64 rng(rd());  // random number generator

  // usedd to generate a seq. of uniformly distributed random digits between 0-9
  std::uniform_int_distribution<int> dist(0,9);

  // create a "decimal_digits"-digits random number
  std::string rand_num = "1";
  for (int i = 0; i < decimal_digits_count - 2; i++) {
    std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
    rand_num += rand_digit;                             // append to random_number
  }
  rand_num += "1";

  int rounds = 40;
  int counter = 0;
  std::cout << "Looking for primes.\n";
  while (!isPrimeMRT(BigInt(rand_num),rounds)) {
    std::cout << "Prime candidates evaluated: " << counter << std::endl;
    if (counter == 1000) {
      throw std::runtime_error("Timeout on prime number generation. Please try again.");
    }
    std::shuffle(rand_num.begin() + 1, rand_num.end() - 1, rng);
    counter++;
  }

  std::cout << "PRIME FOUND: " << rand_num << std::endl;

  return BigInt(rand_num);
}

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
    if (!MRT(d,n)) {
      return false;
    }
  }
  return true;
}

inline 
bool RSA::MRT(BigInt d, BigInt n) {
  BigInt a = randomBigIntInRange(2,n-BigInt(1));
  BigInt x = binPow(a,d,n);

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

  std::string randomDigits = ss.str().substr(0,digits_count);
  return BigInt(randomDigits);
}

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

