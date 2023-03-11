/* Example driver application for RSA class */
/* Author: Lucas Hirt */

#include "RSA.cpp"

int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 50;

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // check initialized class values
  rsa_0.debug();

  // example encryption
  const std::string message_0[5] = {"NIC","EWE","ATH","ERT","ODA"};
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.encrypt(message_0[i]);
    std::string decrypted = rsa_0.decrypt(ciphertext);
    std::cout << message_0[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  const std::string message_1[5] = { "IMI", "SSM", "YGI", "RLF", "RIE" };
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.encrypt(message_1[i]);
    std::string decrypted = rsa_0.decrypt(ciphertext);
    std::cout << message_1[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  const std::string message_2[5] = { "aBi", "GmA", "N-E", "NTT", "TO-" };
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.encrypt(message_2[i]);
    std::string decrypted = rsa_0.decrypt(ciphertext);
    std::cout << message_2[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  return 0;
}

