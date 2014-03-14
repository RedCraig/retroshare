#CXX defaults to g++
CXXFLAGS = -Wall -g -I..

LIB_TOP_DIR = ../..
RSLIBDIR = $(LIB_TOP_DIR)/../libretroshare
LIBS = -L../lib -lbitdht -lpthread -L$(RSLIBDIR)/src/lib -lretroshare -lcrypto

# OK. So in the current dir, /libbitdht/src/auth
# we're including
# #include "../../libretroshare/src/util/rsaes.h"
# in AuthCryptoFns.h.
# To include a header from another lib you need to give the compiler an include path
# and also the lib file to link against.
# Instead I'm giving it the liv (see -Lretroshare opt above) and including the
# file using it's relative path to the current directory.
# INCPATH = -I$(RSLIBDIR)/src
# the above INCPATH path should expand to:
# INCPATH = -I../../../libretroshare/src

EXEC = runtests
EGOBJ = Storage.o AuthCryptoFns.o PasswordAuth.o tests.o udpbitdht_msgtest.o

all: tests

tests: $(EGOBJ)
	$(CXX) $(CXXFLAGS) -o $(EXEC) $(EGOBJ) $(LIBS)

clean:
	rm -f $(EGOBJ) $(EXEC)
