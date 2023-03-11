/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "RSA.cpp"

// struct Codebook {
//   Codebook():
//     char_num({
//       {'a',0}, {'b',1}, {'c',2}, {'d',3}, {'e',4}, {'f',5},
//       {'g',6}, {'h',7}, {'i',8}, {'j',9}, {'k',10},
//       {'l',11}, {'m',12}, {'n',13}, {'o',14}, {'p',15},
//       {'q',16}, {'r',17}, {'s',18}, {'t',19}, {'u',20},
//       {'v',21}, {'w',22}, {'x',23}, {'y',24}, {'z',25}
//       }),
//     num_char({
//       {0,'a'}, {1,'b'}, {2,'c'}, {3,'d'}, {4,'e'}, {5,'f'},
//       {6,'g'}, {7,'h'}, {8,'i'}, {9,'j'}, {10,'k'},
//       {11,'l'}, {12,'m'}, {13,'n'}, {14,'o'}, {15,'p'},
//       {16,'q'}, {17,'r'}, {18,'s'}, {19,'t'}, {20,'u'},
//       {21,'v'}, {22,'w'}, {23,'x'}, {24,'y'}, {25,'z'},
//       }) {
//   }

//   int char_to_num(const char& c) { try { return char_num.at(char(tolower(c))); } catch (std::range_error& ex) { throw ex; } }
//   char int_to_char(const int& x) { return num_char[x]; }

// private:
//   std::unordered_map<char, int> char_num;
//   std::unordered_map<int, char> num_char;
// };

// BigInt fastModExpBigInt(BigInt a, BigInt b, BigInt m) {
//   BigInt f(1);
//   a = a % m;

//   while (b > BigInt(0)) {     // Figure 9.8: for i = k until i = 0
//     if (b.isOdd())            // Figure 9.8:  if b_i = 1 
//       f = (f * a) % m;
//     a = (a * a) % m;
//     b = b / 2;                // Figure 9.8:  c <- 2 * c
//   }

//   return f;
// }

// BigInt e = 7;
// BigInt n = 42607;
// BigInt d = 6023;

// std::string encrypt_plaintext_block(const std::string& plaintext, Codebook codebook) {
//   BigInt trigraph = 0;
//   for (int i = 0; i < plaintext.size(); i++) {
//     trigraph += codebook.char_to_num(plaintext[i]) * pow(26, (plaintext.size() - 1) - i);
//   }

//   BigInt ciphertext_number = fastModExpBigInt(trigraph, e, n);

//   std::string ciphertext_string = "";
//   for (int i = 0; i < plaintext.size(); i++) {
//     long long val = ((ciphertext_number / BigInt::pow(26, plaintext.size() - i)) + 65).longValue();
//     ciphertext_string += char(val);
//     ciphertext_number = ciphertext_number % BigInt::pow(BigInt(26), int(plaintext.size() - i));
//   }
//   long long val = ((ciphertext_number % 26) + 65);
//   ciphertext_string += char(val);

//   return ciphertext_string;
// }

// std::string decrypt_ciphertext_block(const std::string& ciphertext, Codebook codebook) {
//   BigInt val = 0;
//   for (int i = 0; i < ciphertext.size(); i++) {
//     val += BigInt::pow(26,(ciphertext.size() - 1 - i)) * codebook.char_to_num(ciphertext[i]);
//   }

//   BigInt val_mod = fastModExpBigInt(val,d,n);

//   std::string plaintext_string = "";
//   for (int i = 0; i < ciphertext.size() - 2; i++) {
//     plaintext_string += codebook.int_to_char((val_mod / BigInt::pow(BigInt(26),ciphertext.size() - 2 - i)).longValue());
//     val_mod = val_mod % BigInt::pow(BigInt(26), ciphertext.size() - 2 - i);
//   }
//   plaintext_string += codebook.int_to_char(val_mod % 26);

//   return plaintext_string;
// }


int main() {
  // specify how many digits our RSA primes should be
  int prime_digits = 25;

  // initialize the RSA crypto-system
  RSA rsa_0(prime_digits);

  // check initialized class values
  rsa_0.debug();

  // example encryption
  std::string message = "NIC";
  std::string ciphertext_block = rsa_0.encrypt(message);
  std::cout << "cipher block: " << ciphertext_block << std::endl;
  std::string deciphered_ciphertext = rsa_0.decrypt(ciphertext_block);
  std::cout << deciphered_ciphertext << std::endl;

  return 0;
}

