KDIR := /lib/modules/$(shell uname -r)/build
CC = gcc -Wall -Werror

all: fork exec select logging test setVectorOnce listVectors readonly accessControl refcounting setVectorOnceChild paramvalidate snoop

##### USER PROGRAMS HERE ####
logging: logging.c
	$(CC) logging.c -I$(KDIR)/include -o logging
refcounting: refcounting.c
	$(CC) refcounting.c -I$(KDIR)/include -o refcounting
readonly: readonly.c
	$(CC) readonly.c -I$(KDIR)/include -o readonly
accessControl: accessControl.c
	$(CC) accessControl.c -I$(KDIR)/include -o accessControl
paramvalidate: paramvalidate.c
	$(CC) paramvalidate.c -I$(KDIR)/include -o paramvalidate
test: test.c
	$(CC) test.c -I$(KDIR)/include -o test
fork: fork.c
	$(CC) fork.c -I$(KDIR)/include -o fork
exec: exec.c
	$(CC) exec.c -I$(KDIR)/include -o exec
select: select.c
	$(CC) select.c -I$(KDIR)/include -o select
snoop: snoop.c
	$(CC) snoop.c -I$(KDIR)/include -o snoop
setVectorOnce: setVectorOnce.c
	$(CC) setVectorOnce.c -I$(KDIR)/include -o setVectorOnce
setVectorOnceChild: setVectorOnceChild.c
	$(CC) setVectorOnceChild.c -I$(KDIR)/include -o setVectorOnceChild
listVectors: listVectors.c
	$(CC) listVectors.c -I$(KDIR)/include -o listVectors
#############################
clean:
	rm -rf refcounting fork exec select logging test setVectorOnce listVectors readonly accessControl setVectorOnceChild paramvalidate snoop
