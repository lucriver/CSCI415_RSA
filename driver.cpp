/* Example driver application for RSA class */
/* Author: Lucas Hirt */

#include "RSA.cpp"

const int MAX_PRIME_DIGITS = 300;
const int MIN_PRIME_DIGITS = 3;

int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 0;
  std::cout << "Enter number indicating # of digits for RSA primes > ";
  std::cin >> prime_digits;
  while (MIN_PRIME_DIGITS < 3 || prime_digits > MAX_PRIME_DIGITS) {
    std::cout << "Invalid number entered. Try again > ";
    std::cin >> prime_digits;
  }

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // encryption and decryption
  int choice = 0;
  while (1) {
    std::cout << "Please choose from the following:\n";
    std::cout << "1: Encrypt and decrypt a message.\n";
    std::cout << "2: Encrypt and decrypt a plaintext file.\n";
    std::cout << "3: Quit\n";
    std::cin >> choice;
    switch (choice) {
      case (1): {
        std::string plaintext;
        std::cout << "Enter a 3-character message to encrypt (only letters): ";
        std::cin >> plaintext;
        std::cout << "Plaintext: " << plaintext << std::endl;
        std::string ciphertext = rsa_0.encrypt(plaintext);
        std::cout << "Ciphertext: " << ciphertext << std::endl;
        std::string decrypted = rsa_0.decrypt(ciphertext);
        std::cout << "Decrypted ciphertext: " << decrypted << std::endl;
        continue;
      }
      case (2) : {
        std::string fname_in;
        std::cout << "Please enter a filename that contains plaintext to encrypt: ";
        std::cin >> fname_in;
        std::string fname_out;
        std::cout << "Please enter the filename to output encrypted plaintext to: ";
        std::cin >> fname_out;
        rsa_0.file_encrypt(fname_in,fname_out);
        std::string fname_out_out;
        std::cout << "Please enter the filename to output decrypted ciphertext to: ";
        std::cin >> fname_out_out;
        rsa_0.file_decrypt(fname_out,fname_out_out);
        continue;
      }
      case (3) : {
        std::cout << "Terminating program.\n";
        break;
      }
      default : {
        std::cout << "Invalid option chosen.\n";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        continue;
      }
    }
    break;
  }

  return 0;
}
