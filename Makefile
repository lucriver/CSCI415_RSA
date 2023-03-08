CC = g++
CFLAGS = -Wall -g -std=c++11
TARGET = driver
SRC = RSA.cpp BigInt.cpp driver.cpp

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)