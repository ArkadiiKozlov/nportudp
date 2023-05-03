obj-m:=nportudp.o

KSOURCE = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KSOURCE) M=$(shell pwd) modules

clean:
	make -C $(KSOURCE) M=$(shell pwd) clean