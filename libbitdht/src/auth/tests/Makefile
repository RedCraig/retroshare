
CXXFLAGS = -Wall -g -I..
#CXXFLAGS += -arch i386 # OSX

LIBS = -L../../lib -lbitdht -lpthread
#-L../../../../libretroshare/src/lib -libretroshare.a


EXEC : crypto_test
EGOBJ = crypto_test.o

crypto_test: $(EGOBJ)
	$(CXX) $(CXXFLAGS) -o crypto_test $(EGOBJ) $(LIBS)


