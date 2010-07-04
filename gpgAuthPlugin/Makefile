CPP = g++
CPPFLAGS = -g -Wall -lgpgme -lgpg-error
LDFLAGS = -lm -DDEBUG

# Compile the program.
gpgauth : gpgauth.cpp
	$(CPP) $(CPPFLAGS) -o gpgauth gpgauth.cpp $(LDFLAGS)

# command to be executed.
clean:
	rm gpgauth
