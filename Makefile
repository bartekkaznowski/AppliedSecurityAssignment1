modmul : $(wildcard *.[ch])
	@gcc -Wall -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -lgmp -lm librdrand.a -lcrypto

.DEFAULT_GOAL = all

all   : modmul

clean : 
	@rm -f core modmul
