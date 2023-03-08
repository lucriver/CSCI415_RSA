/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "RSA.cpp"


int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 101;

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // check initialized class values
  rsa_0.debug();

  return 0;
}

