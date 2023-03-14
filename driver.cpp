/* Example driver application for RSA class */
/* Author: Lucas Hirt */

#include "RSA.cpp"

void basic_test(RSA);

int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 3;

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // // check initialized class values
  rsa_0.debug();

  // // basic test 
  basic_test(rsa_0);

  // const std::string file_plaintext = "plaintext_0.txt";
  // const std::string file_ciphertext = "ciphertext_0.txt";
  // const std::string file_decrypted_ciphertext = "decrypted_0.txt";
  // std::cout << "encrypting file: " << file_plaintext << std::endl;
  // rsa_0.file_encrypt(file_plaintext,file_ciphertext);
  // rsa_0.file_decrypt(file_ciphertext,file_decrypted_ciphertext);
  // std::cout << "File decrypted. Output file name: " << file_decrypted_ciphertext << std::endl;


  return 0;
}

void basic_test(RSA rsa_0) {
  // example encryption
  const std::string message_0[5] = {"NIC","EWE","ATH","ERT","ODA"};
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.temp_encrypt(message_0[i]);
    std::string decrypted = rsa_0.temp_decrypt(ciphertext);
    std::cout << message_0[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  const std::string message_1[5] = { "IMI", "SSM", "YGI", "RLF", "RIE" };
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.temp_encrypt(message_1[i]);
    std::string decrypted = rsa_0.temp_decrypt(ciphertext);
    std::cout << message_1[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  const std::string message_2[5] = { "aBi", "GmA", "N-E", "NTT", "TO-" };
  for (int i=0;i<5;i++) {
    std::string ciphertext = rsa_0.temp_encrypt(message_2[i]);
    std::string decrypted = rsa_0.temp_decrypt(ciphertext);
    std::cout << message_2[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl;

  const std::string message_3[14] = { "HIM", "YNA", "MEI", "SLU", "CAS", "AND", "ILI", "KET", "TOP", "LAY", "VID", "EOG", "AME", "S--" };
  for (int i=0;i<14;i++) {
    std::string ciphertext = rsa_0.temp_encrypt(message_3[i]);
    std::string decrypted = rsa_0.temp_decrypt(ciphertext);
    std::cout << message_3[i] << " -> " << ciphertext << " -> " << decrypted << std::endl;
  }
  std::cout << std::endl; 
}