/* BigInt class definition that allows for RSA-relevant arithemetic operations on very large numbers. */
/* Authors: Lucas Hirt */

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

class BigInt {
  public:
  static const unsigned long long int BASE = 10;

  // Constructors
  BigInt(): digits(1, 0), negative(false) {}
  BigInt(const std::string& num_str);

  // Copy Constructor
  BigInt(const BigInt& other);

  // Assignment Operator
  BigInt& operator=(const BigInt& other);

  // Addition Operator
  BigInt operator+(const BigInt& other) const;

  // Subtraction Operator
  BigInt operator-(const BigInt& other) const;

  // Multiplication Operator
  BigInt operator*(const BigInt& other) const;

  // Division Operator
  //BigInt operator/(const BigInt& rhs) const;

  // Modulus Operator
  BigInt operator%(const BigInt& rhs) const;

  // Comparison Operators
  bool operator==(const BigInt& other) const;
  bool operator<(const BigInt& other) const;

  // Stream Operator
  friend std::ostream& operator<<(std::ostream& os, const BigInt& num);

  private:
  std::vector<int> digits;
  bool negative;

  // Helper functions
  void removeLeadingZeros();
  BigInt flipSign();
  BigInt abs() const;
};

// --- public methods ---

inline
BigInt::BigInt(const std::string& num_str) {
  std::string str = num_str;
  if (str[0] == '-') {
    negative = true;
    str = str.substr(1);
  }
  else {
    negative = false;
  }

  for (int i = str.length() - 1; i >= 0; i--) {
    digits.push_back(str[i] - '0');
  }

  removeLeadingZeros();
}

inline
BigInt::BigInt(const BigInt& other) {
  digits = other.digits;
  negative = other.negative;
}

inline
BigInt& BigInt::operator=(const BigInt& other) {
  if (this == &other) {
    return *this;
  }
  digits = other.digits;
  negative = other.negative;
  return *this;
}

inline
BigInt BigInt::operator+(const BigInt& other) const {
  if (negative != other.negative) {
    return *this - other.abs();
  }

  BigInt result;
  result.digits.clear();
  int carry = 0;
  int max_size = std::max(digits.size(), other.digits.size());

  for (int i = 0; i < max_size || carry; i++) {
    int sum = carry;
    if (i < digits.size()) {
      sum += digits[i];
    }
    if (i < other.digits.size()) {
      sum += other.digits[i];
    }
    result.digits.push_back(sum % 10);
    carry = sum / 10;
  }

  result.negative = negative;
  result.removeLeadingZeros();
  return result;
}

inline
BigInt BigInt::operator-(const BigInt& other) const {
  if (negative != other.negative) {
    return *this + other.abs();
  }

  if (abs() < other.abs()) {
    return (other - *this).flipSign();
  }

  BigInt result;
  result.digits.clear();
  int borrow = 0;
  int max_size = std::max(digits.size(), other.digits.size());

  for (int i = 0; i < max_size || borrow; i++) {
    int diff = borrow;
    if (i < digits.size()) {
      diff += digits[i];
    }
    if (i < other.digits.size()) {
      diff -= other.digits[i];
    }
    if (diff < 0) {
      diff += 10;
      borrow = -1;
    }
    else {
      borrow = 0;
    }
    result.digits.push_back(diff);
  }

  result.negative = negative;
  result.removeLeadingZeros();
  return result;
}

inline
BigInt BigInt::operator*(const BigInt& other) const {
  BigInt result;
  result.digits.assign(digits.size() + other.digits.size(), 0);
  result.negative = negative != other.negative;

  for (int i = 0; i < digits.size(); i++) {
    int carry = 0;
    for (int j = 0; j < other.digits.size() || carry; j++) {
      long long prod = result.digits[i + j] +
        static_cast<long long>(digits[i]) * (j < other.digits.size() ? other.digits[j] : 0) + carry;
      result.digits[i + j] = static_cast<int>(prod % 10);
      carry = static_cast<int>(prod / 10);
    }
  }

  result.removeLeadingZeros();
  return result;
}

// division (/) here

inline
BigInt BigInt::operator%(const BigInt& rhs) const {
  if (rhs == BigInt(std::to_string(0))) {
    std::cerr << "Error: division by zero" << std::endl;
    return BigInt();
  }

  BigInt dividend = this->abs(), divisor = rhs.abs(), remainder;

  for (int i = dividend.digits.size() - 1; i >= 0; --i) {
    remainder = remainder * BigInt(std::to_string(BASE)) + BigInt(std::to_string(dividend.digits[i]));
    if (divisor < remainder || divisor == remainder) {
      remainder = remainder - divisor;
    }
  }

  remainder.negative = (this->negative != rhs.negative);

  return remainder;
}

inline
bool BigInt::operator==(const BigInt& other) const {
  return negative == other.negative && digits == other.digits;
}

inline
bool BigInt::operator<(const BigInt& other) const {
  if (negative != other.negative) {
    return negative;
  }

  if (digits.size() != other.digits.size()) {
    return (digits.size() < other.digits.size()) ^ negative;
  }

  for (int i = digits.size() - 1; i >= 0; i--) {
    if (digits[i] != other.digits[i]) {
      return (digits[i] < other.digits[i]) ^ negative;
    }
  }

  return false;
}

inline
std::ostream& operator<<(std::ostream& os, const BigInt& num) {
  if (num.negative) {
    os << '-';
  }
  for (int i = num.digits.size() - 1; i >= 0; i--) {
    os << num.digits[i];
  }
  return os;
}



// --- private methods ---

inline
BigInt BigInt::flipSign() {
  BigInt result(*this);
  result.negative = !negative;
  return result;
}

inline
void BigInt::removeLeadingZeros() {
  while (digits.size() > 1 && digits.back() == 0) {
    digits.pop_back();
  }

  if (digits.size() == 1 && digits[0] == 0) {
    negative = false;
  }
}

inline
BigInt BigInt::abs() const {
  BigInt result(*this);
  result.negative = false;
  return result;
}