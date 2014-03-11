
CXXFLAGS = -Wall -g -I..
#CXXFLAGS += -arch i386 # OSX

LIBS = -L../lib -lbitdht -lpthread -L../../../libretroshare/src/lib -lretroshare -lcrypto

EXEC : tests
EGOBJ = Storage.o AuthCryptoFns.o PasswordAuth.o tests.o

all: tests

tests: $(EGOBJ)
	$(CXX) $(CXXFLAGS) -o tests $(EGOBJ) $(LIBS)

