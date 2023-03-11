/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "RSA.cpp"

int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 100;

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // check initialized class values
  // rsa_0.debug();

  // example encryption
  const std::string message_0[5] = {"NIC","EWE","ATH","ERT","ODA"};
  for (int i=0;i<5;i++) {
    std::cout << rsa_0.decrypt(rsa_0.encrypt(message_0[i])) << " ";
  }
  std::cout << std::endl;

  const std::string message_1[5] = { "IMI", "SSM", "YGI", "RLF", "RIE" };
  for (int i=0;i<5;i++) {
    std::cout << rsa_0.decrypt(rsa_0.encrypt(message_1[i])) << " ";
  }
  std::cout << std::endl;

  const std::string message_2[5] = { "aBi", "GmA", "NWE", "NTT", "TOU" };
  for (int i=0;i<5;i++) {
    std::cout << rsa_0.decrypt(rsa_0.encrypt(message_2[i])) << " ";
  }
  std::cout << std::endl;

  // std::string message = "NIC";
  // std::string ciphertext_block = rsa_0.encrypt(message);
  // std::string deciphered_ciphertext = rsa_0.decrypt(ciphertext_block);
  // std::cout << "\nmessage: " << message << std::endl;
  // std::cout << "ciphertext: " << ciphertext_block << std::endl;
  // std::cout << "deciphered: " << deciphered_ciphertext << std::endl;

  return 0;
}

