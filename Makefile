CC = g++
CFLAGS = -Wall -g
TARGET = driver
SRC = RSA.cpp BigInt.cpp driver.cpp

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)