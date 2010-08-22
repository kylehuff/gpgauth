# This Makefile is to compile the gpgauth binary only - which
#   would only be useful for testing. The NPAPI plugin that 
#   uses this is compiled using Firebreath, and must be built
#   under that environment.

CPP = g++
CPPFLAGS = -g -Wall -lgpgme -lgpg-error
LDFLAGS = -lm -DDEBUG

# Compile the program.
gpgauth : gpgauth.cpp
	$(CPP) $(CPPFLAGS) -o gpgauth gpgauth.cpp $(LDFLAGS)

# command to be executed.
clean:
	rm gpgauth
