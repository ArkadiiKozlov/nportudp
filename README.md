# nportudp
This is a driver for nport moxa devices. The driver requiers the UDP mode on the nport.
An user application opens a /dev/ttyrXX device as a usual serial port. Speed, mode, parity 
and other parameters are configured at the nport device. while supported only one device: 
/dev/ttyr0, nport IP address should be 192.168.254.125, port 4001
