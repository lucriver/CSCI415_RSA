/* RSA class definition */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <random>
#include <algorithm>

class RSA {
  public:
    RSA();
    ~RSA();
    void test();

  private:

};

// -------------- Public methods --------------

RSA::RSA() { }

RSA::~RSA() { }

void RSA::test() {

}


// -------------- Private methods --------------


// std::string RSA::generate_random_prime(int digits) {
//   std::random_device rd;    // generate seed for random number generator (rng)
//   std::mt19937_64 rng(rd());  // random number generator

//   // usedd to generate a seq. of uniformly distributed random digits between 0-9
//   std::uniform_int_distribution<int> dist(0,9);

//   // create a 100-digit random number
//   std::string rand_num = "1";
//   for (int i = 0; i < digits - 2; i++) {
//     std::string rand_digit = std::to_string(dist(rng)); // get 1-digit rand between 0-9
//     rand_num += rand_digit;                             // append to random_number
//   }
//   rand_num += "1";

//   // verify 100-digit random-number is prime, modifying if necessary
//   while (!is_prime_rabin_miller(std::stoll(rand_num))) { 
//     std::shuffle(rand_num.begin() + 1, rand_num.end() - 1, rng);
//   }
    


//   std::cout << dist(rng);
//   return 0;
// }

