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

  // example
  std::string message = "17";
  std::string encoded_message = rsa_0.encrypt(message);
  std::string decoded_message = rsa_0.decrypt(encoded_message);
  std::cout << "plaintext: " << message << std::endl;
  std::cout << "ciphertext: " << encoded_message << std::endl;
  std::cout << "decoded ciphertext: " << decoded_message << std::endl;

  return 0;
}

