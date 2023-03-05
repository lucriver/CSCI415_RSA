/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "BigInt.cpp"

int main() {
  std::string p = "738530873350358193163232517286281434330533510748956";
  std::string q = "879490751145346669372531892076489380197698665212769";
  BigInt x(p);
  BigInt y(q);
  BigInt add = x + y;
  BigInt sub_0 = x - y;
  BigInt sub_1 = y - x;
  BigInt mult = x * y;
  std::cout << add << std::endl;
  std::cout << sub_0 << std::endl;
  std::cout << sub_1 << std::endl;
  std::cout << mult << std::endl;
  return 0;
}