all: maya brain stripx stub
maya: eh_frame.o profile.o disas.o main.o util.o elf.o checker.o cflow.o fp.o nanomite.o crypto.o ecrypt.o
	gcc -g eh_frame.o profile.o disas.o main.o util.o elf.o checker.o fp.o cflow.o nanomite.o crypto.o ecrypt.o -o maya -ludis86 -ldwarf -lelf
main.o: main.c
	gcc -c main.c
util.o: util.c
	gcc -c util.c
elf.o: elf.c
	gcc -c elf.c
checker.o: checker.c
	gcc -c checker.c
cflow.o: cflow.c
	gcc -c cflow.c
fp.o: fp.c
	gcc -c fp.c
disas.o: disas.c
	gcc -c disas.c
nanomite.o: nanomite.c
	gcc -c nanomite.c
crypto.o: crypto.c
	gcc -c crypto.c
ecrypt.o: ecrypt.c
	gcc -c ecrypt.c
profile.o: profile.c
	gcc -ggdb -c profile.c
eh_frame.o: eh_frame.c
	gcc -c eh_frame.c

brain:
	gcc -DHEAP_CRYPTO -DOPAQUE_BRANCHES -DDISPLAY_CFLOW -DDISPLAY_MSG -c tracer.c
	cp tracer.o runtime_engine_stubs
stripx:
	gcc -O2 utils/stripx.c -o stripx
	
stub: 
	./makestub.sh
	cp stub runtime_engine_stubs
	./stripx stub
	./stripx runtime_engine_stubs/stub

clean:
	rm -f tracer.o *.o maya tracer stub
