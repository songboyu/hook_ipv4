objects =  nlusr.o

nlusr : $(objects)
	gcc -o nlusr $(objects) -lz
nlusr.o : nlusr.c
	gcc -c nlusr.c

clean:
	rm nlusr $(objects)