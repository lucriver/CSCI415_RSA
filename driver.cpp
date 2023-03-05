/* Example driver application for RSA class */
/* Authors: Lucas Hirt */

#include "BigInt.cpp"

int main() {
  std::string p = "302663234051331038391380346924549362645708778812240";
  std::string q = "584174259524812845505854918801946430109501235279851";
  BigInt x(p);
  BigInt y(q);
  BigInt add = x + y;
  BigInt sub_0 = x - y;
  BigInt sub_1 = y - x;
  BigInt mult = x * y;
  BigInt mod_0 = y % x;
  std::cout << mod_0 << std::endl;
  return 0;
}