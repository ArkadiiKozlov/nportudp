obj-m:=nportudp.o

KSOURCE = /lib/modules/$(shell uname -r)/build

all:
#	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
#	make -C ../Exp/linux-4.14.31 M=$(shell pwd) modules
	make -C $(KSOURCE) M=$(shell pwd) modules

clean:
#	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
#	make -C ../Exp/linux-4.14.31 M=$(shell pwd) clean
	make -C $(KSOURCE) M=$(shell pwd) clean