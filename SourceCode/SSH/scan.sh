service ssh restart
iptables -F
iptables -I INPUT -j ACCEPT
rm notice.log
zeekctl start
zeek -C -i h1-eth0 sshAttack.zeek
