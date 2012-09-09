obj-m := sys_vector.o
obj-m += vector1.o
obj-m += vector2.o
obj-m += vector_logging.o
obj-m += vector_readonly.o
obj-m += vector_access.o
obj-m += vector_params.o
obj-m += vector_refcount.o
obj-m += vector_prohibit.o
obj-m += vector_snoop.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC = gcc -Wall -Werror

all: sys_vector vector1 vector2 vector_logging vector_readonly vector_access vector_params vector_refcount vector_prohibit vector_snoop

#### KERNEL MODULES HERE ####
sys_vector:
	make -C $(KDIR) M=$(PWD) modules

vector1:
	make -C $(KDIR) M=$(PWD) modules

vector2:
	make -C $(KDIR) M=$(PWD) modules

vector_logging:
	make -C $(KDIR) M=$(PWD) modules

vector_readonly:
	make -C $(KDIR) M=$(PWD) modules

vector_access:
	make -C $(KDIR) M=$(PWD) modules

vector_params:
	make -C $(KDIR) M=$(PWD) modules
vector_refcount:
	make -C $(KDIR) M=$(PWD) modules
vector_prohibit:
	make -C $(KDIR) M=$(PWD) modules
vector_snoop:
	make -C $(KDIR) M=$(PWD) modules
#############################

clean:
	make -C $(KDIR) M=$(PWD) clean
