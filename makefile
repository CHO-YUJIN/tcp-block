LDLIBS=-lpcap
all: test
test: main.o arphdr.o ethhdr.o ip.o iphdr.o tcphdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
clean: rm -f test *.o
