/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "BigInt.cpp"

int main() {
  std::string p = "8086164800307799455819351967011177666191433164738525272320237134651610279573873606606310942657291329";
  std::string q = "71805181950095383895661116778076595983476969841596584002868398296678459126834594575951122475032232675";
  BigInt x(p);
  BigInt y(q);
  BigInt add = x + y;
  BigInt sub_0 = x - y;
  BigInt sub_1 = y - x;
  BigInt mult = x * y;
  BigInt mod_0 = y % x;
  BigInt mod_1 = x % y;
  std::cout << add << std::endl;
  std::cout << mult << std::endl;
  std::cout << sub_0 << std::endl;
  std::cout << sub_1 << std::endl;
  std::cout << mod_0 << std::endl;
  std::cout << mod_1 << std::endl;
  return 0;
}