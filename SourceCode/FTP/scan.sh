service vsftpd restart
iptables -F
iptables -I INPUT -j ACCEPT
rm notice.log
zeekctl start
zeek -C -i enp0s3 ftpAttack.zeek
