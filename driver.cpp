/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "RSA.cpp"

int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 100;

  // initialize the RSA crypto-system
  RSA rsa_system(prime_digits);

  return 0;
}

