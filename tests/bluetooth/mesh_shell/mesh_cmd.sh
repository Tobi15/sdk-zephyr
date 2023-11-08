mesh init
mesh prov local 0 0x0001
mesh models cfg appkey add 0 0
mesh models cfg net-transmit-param 0 20 
mesh target dst 10
mesh target net 0
mesh target app 0
mesh test net-send abcdef 