#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.

###############################################################################################################
# START_VARIABLE_SECTION
# This section contains setup and variables
###############################################################################################################

TCP_SERVICE_AND_CONFIG_NAME="openvpn_tcp"
UDP_SERVICE_AND_CONFIG_NAME="openvpn_udp"

if [[ "$USER" != 'root' ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi


if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi


if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu or CentOS system"
	exit
fi

###############################################################################################################
# END_VARIABLE_SECTION
###############################################################################################################


newclient () {
	# This function is used to create udp client .ovpn file
	cp /etc/openvpn/client-common.txt ~/"$1.ovpn"
	echo "<ca>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/"$1.ovpn"
	echo "</ca>" >> ~/"$1.ovpn"
	echo "<cert>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/issued/"$1.crt" >> ~/"$1.ovpn"
	echo "</cert>" >> ~/"$1.ovpn"
	echo "<key>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/private/"$1.key" >> ~/"$1.ovpn"
	echo "</key>" >> ~/"$1.ovpn"
	if [ "$TLS" = "1" ]; then  #check if TLS is selected to add a TLS static key
		echo "key-direction 1" >> ~/"$1.ovpn"
		echo "<tls-auth>" >> ~/"$1.ovpn"
		cat /etc/openvpn/easy-rsa/pki/private/ta.key >> ~/"$1.ovpn"
		echo "</tls-auth>" >> ~/"$1.ovpn"
	fi
}


newclienttcp () {
	# This function is used to create tcp client .ovpn file
	cp /etc/openvpn/clienttcp-common.txt ~/"$1tcp.ovpn"
	echo "<ca>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/"$1tcp.ovpn"
	echo "</ca>" >> ~/"$1tcp.ovpn"
	echo "<cert>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/issued/"$1.crt" >> ~/"$1tcp.ovpn"
	echo "</cert>" >> ~/"$1tcp.ovpn"
	echo "<key>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/private/"$1.key" >> ~/"$1tcp.ovpn"
	echo "</key>" >> ~/"$1tcp.ovpn"
	if [ "$TLS" = "1" ]; then  #check if TLS is selected to add a TLS static key
		echo "key-direction 1" >> ~/"$1tcp.ovpn"
		echo "<tls-auth>" >> ~/"$1tcp.ovpn"
		cat /etc/openvpn/easy-rsa/pki/private/ta.key >> ~/"$1tcp.ovpn"
		echo "</tls-auth>" >> ~/"$1tcp.ovpn"
	fi
}


# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi


if [ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf -o -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]; then    #check if udp or tcp config file is present
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1) 
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full "$CLIENT" nopass
			# Generates the custom client.ovpn
			if [[ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf ]]; then
				TLS=0
				if [ -n "$(cat /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | grep tls-auth)" ]; then #check if TLS is enabled in server config file so that static TLS key can be added to new client
					TLS=1 
				fi
				newclient "$CLIENT"
				echo "UDP client $CLIENT added, certs available at ~/$CLIENT.ovpn"
			fi
			
			#everything here is the same as above just for the tcp client
			if [[ -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]]; then
				TLS=0
				if [ -n "$(cat /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf | grep tls-auth)" ]; then
					TLS=1
				fi
				newclienttcp "$CLIENT"
				echo "TCP client $CLIENT added, certs available at ~/${CLIENT}tcp.ovpn"
			fi
			
			echo ""
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke "$CLIENT"
			./easyrsa gen-crl
			# And restart
			
			if pgrep systemd-journal; then
				systemctl restart openvpn
			else
				if [[ "$OS" = 'debian' ]]; then
					/etc/init.d/openvpn restart
				else
					service openvpn restart
				fi
			fi
			
			echo ""
			echo "Certificate for client \"$CLIENT\" revoked"
			exit
			;;
			###############################################################################################################
			# START_OPENVPN_REMOVAL_SECTION
			# This section contains to remove openvpn as installed by this script
			###############################################################################################################
			3)
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
			if [[ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf ]]; then  #removal of udp firewall rules
				PORT=$(grep '^port ' /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | cut -d " " -f 2)
				    iptables -L | grep -q REJECT
					sed -i "/iptables -I INPUT -p udp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
				
				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				fi
				
				if [[ -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]]; then #removal of tcp firewall rules
				PORT=$(grep '^port ' /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf | cut -d " " -f 2)
				
				iptables -L | grep -q REJECT
					sed -i "/iptables -I INPUT -p tcp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.9.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					sed -i '/iptables -t nat -A POSTROUTING -s 10.9.0.0\/24 -j SNAT --to /d' $RCLOCAL
				fi
				apt-get remove --purge -y openvpn openvpn-blacklist bind9 bind9utils bind9-doc clamav clamav-daemon privoxy havp
				
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				if pgrep systemd-journal; then
					sudo systemctl disable $UDP_SERVICE_AND_CONFIG_NAME.service
					sudo systemctl disable $TCP_SERVICE_AND_CONFIG_NAME.service
				fi
				rm -rf /etc/systemd/system/$UDP_SERVICE_AND_CONFIG_NAME.service
				rm -rf /etc/systemd/system/$TCP_SERVICE_AND_CONFIG_NAME.service
				echo ""
				echo "OpenVPN removed!"
				
			fi
			exit
			;;
			###############################################################################################################
			# END_OPENVPN_REMOVAL_SECTION
			###############################################################################################################
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this quick OpenVPN "road warrior" installer'
	echo ""
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP
	echo ""
	while :
	do
	while :
	do
	clear
	read -p "Do you want to run a UDP server [y/n]: " -e -i y UDP
        case $UDP in
	       y)   UDP=1
	    break ;;
	       n)   UDP=0
	     break ;;
        esac
	 done
	 
	 while :
	do
	clear
	echo "***************************************************"
	echo "*                   !!!!!NB!!!!!                  *"
	echo "*                                                 *"
	echo "* Here be dragons!!! If you're using this to get  *"
	echo "* past firewalls then go ahead and choose *y*,    *"
	echo "* but please read and understand                  *"
	echo "*                                                 *"
	echo "* http://sites.inka.de/bigred/devel/tcp-tcp.html  *"
	echo "* http://tinyurl.com/34qzu5z                      *"
	echo "***************************************************"
	echo ""
	read -p "Do you want to run a TCP server [y/n]: " -e -i n TCP
        case $TCP in
	       y)   TCP=1
	    break ;;
	       n)   TCP=0
	     break ;;
        esac
	 done
	 if [ "$UDP" = 1 -o "$TCP" = 1 ]; then
	  break
	  fi
	 done
	 if [ "$UDP" = 1 ]; then
	clear
	read -p "What UDP port do you want to run OpenVPN on?: " -e -i 1194 PORT
	 fi
	 if [ "$TCP" = 1 ]; then
	clear
	read -p "What TCP port do you want to run OpenVPN on?: " -e -i 443 PORTTCP
	 fi
       while :
	do
	clear
	echo "What size do you want your key to be? :"
	echo "     1) 2048bits"
	echo "     2) 4096bits"
	echo ""
	read -p "Key Size [1-2]: " -e -i 1 KEYSIZE
	case $KEYSIZE in
		1)
			KEYSIZE=2048
			break
		;;
		2)
			KEYSIZE=4096
			break
		;;
	esac
	done
	
	 while :
	do
	clear
	echo "What size do you want your SHA digest to be? :"
	echo "     1) 256bits"
	echo "     2) 512bits"
	echo ""
	read -p "Digest Size [1-2]: " -e -i 1 DIGEST
	case $DIGEST in
		1)
			DIGEST=SHA256
			break
		;;
        2)
			DIGEST=SHA512
			break
		;;	
	esac
	done
	
	while :
	do
	clear
	 echo "Which cipher do you want to use? :"
	 echo "     1) AES-256-CBC"
	 echo "     2) AES-128-CBC"
	 echo "     3) BF-CBC"
	 echo "     4) CAMELLIA-256-CBC"
	 echo "     5) CAMELLIA-128-CBC"
	 echo ""    
	read -p "Cipher [1-5]: " -e -i 1 CIPHER
	 case $CIPHER in
	    1) CIPHER=AES-256-CBC
		 break ;;
		2) CIPHER=AES-128-CBC
         break ;;
        3) CIPHER=BF-CBC
         break ;;	
        4) CIPHER=CAMELLIA-256-CBC
         break ;;
        5) CIPHER=CAMELLIA-128-CBC
         break ;;
        esac		  
	done   
    while :
    do
    clear
    read -p "Do you want to use additional TLS authentication [y/n]: " -e -i y TLS
     case $TLS in
      y) TLS=1
      break ;;
      n) TLS=0
      break ;;
      esac
      done
      
      while :
    do
    clear
    echo "Do you want to enable internal networking for the VPN(iptables only)?"
	echo "This can allow VPN clients to communicate between them"
	read -p "Allow internal networking [y/n]: " -e -i y INTERNALNETWORK
     case $INTERNALNETWORK in
      y) INTERNALNETWORK=1
      break ;;
      n) INTERNALNETWORK=0
      break ;;
      esac
      done
     while :
     do
      clear
         echo "Do you want to create self hosted DNS resolver ?"
         echo "This resolver will be only accessible through VPN to prevent"
         echo "your server to be used for DNS amplification attack"
           read -p "Create DNS resolver [y/n]: " -e -i n DNSRESOLVER
           case $DNSRESOLVER in
            y) DNSRESOLVER=1
              break;;
            n) DNSRESOLVER=0
              break;;
            esac
     done
     
     while :
     do
       clear
        echo "Do you want to setup Privoxy+ClamAV+HAVP?"
        echo "Privoxy will be used to block ads."
        echo "ClamAV+HAVP will be used to scan all of your web traffic for viruses."
        echo "This will only work with unencrypted traffic."
        echo "You should have at least 1GB RAM for this option."
        read -p "[y/n]: " -e -i n ANTIVIR
        case $ANTIVIR in
        y) ANTIVIR=1
           break;;
        n) ANTIVIR=0
           break;;
        esac
      done
        
	clear
	if [ "$DNSRESOLVER" = 0 ]; then    #If user wants to use his own DNS resolver this selection is skipped
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) OpenDNS"
	echo "   3) Level 3"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Google"
	echo ""
	read -p "DNS [1-6]: " -e -i 1 DNS
    fi
       
	clear
	echo "Finally, tell me your name for the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
		if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl -y
		
		if [ "$DNSRESOLVER" = 1 ]; then
        DNS=7
        #Installation of BIND9 caching DNS resolver
           sudo apt-get install bind9 bind9utils bind9-doc -y
           if [ "$UDP" = 1 ]; then
            sed -i '/listen-on-v6/a \
                    listen-on { 10.8.0.1;};' /etc/bind/named.conf.options
           fi
           
			if [ "$TCP" = 1 ]; then 
			 sed -i '/listen-on-v6/a \
					listen-on { 10.9.0.1;};' /etc/bind/named.conf.options
			fi
         sed -i '/listen-on-v6/a \
         allow-recursion { 0.0.0.0/0; };' /etc/bind/named.conf.options  #We will permit recursion from any IP(0.0.0.0/0) because our DNS resolver is listening only on our VPN network so it is not a security issue
         sed -i '/listen-on-v6/d' /etc/bind/named.conf.options  
       fi
 if [ "$ANTIVIR" = 1 ]; then 
             apt-get install clamav clamav-daemon -y
 service clamav-freshclam stop
 freshclam
 service clamav-freshclam start
 sed -i "s/AllowSupplementaryGroups false/AllowSupplementaryGroups true/" /etc/clamav/clamd.conf
 service clamav-daemon restart
 apt-get install havp -y
sed -i '/ENABLECLAMLIB true/c\ENABLECLAMLIB false'  /etc/havp/havp.config
sed -i '/ENABLECLAMD false/c\ENABLECLAMD true'  /etc/havp/havp.config
sed -i '/RANGE false/c\RANGE true'  /etc/havp/havp.config
sed -i '/SCANIMAGES true/c\ENABLECLAMD false'  /etc/havp/havp.config
sed -i 's/\# SKIPMIME/SKIPMIME/'  /etc/havp/havp.config
sed -i '/\LOG_OKS true/c\LOG_OKS false'  /etc/havp/havp.config
 gpasswd -a clamav havp
 service clamav-daemon restart
 service havp restart
 apt-get install privoxy -y
sed -i '/listen-address  localhost:8118/c\listen-address  127.0.0.1:8118' /etc/privoxy/config
HOST=$(hostname -f)
sed -i "/hostname hostname.example.org/c\hostname "$HOST""  /etc/privoxy/config
 service privoxy restart
sed -i '/PARENTPROXY localhost/c\PARENTPROXY 127.0.0.1'  /etc/havp/havp.config
sed -i '/PARENTPORT 3128/c\PARENTPORT 8118'  /etc/havp/havp.config
sed -i '/TRANSPARENT false/c\TRANSPARENT true'  /etc/havp/havp.config
sed -i "3 a\iptables -t nat -A PREROUTING -p tcp -i tun+ --dport 80 -j REDIRECT --to-port 8080" /etc/rc.local  #Add this firewall rule to startup(redirect traffic on port 80 to privoxy) 
 service havp restart
iptables -t nat -A PREROUTING -i tun+ -p tcp --dport 80 -j REDIRECT --to-port 8080
 fi
	else
		echo "Only Debian-based distros supported currently"
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget --no-check-certificate -O ~/EasyRSA-3.0.0.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.0/EasyRSA-3.0.0.tgz
	tar xzf ~/EasyRSA-3.0.0.tgz -C ~/
	mv ~/EasyRSA-3.0.0/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.0/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.0.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	cp vars.example vars
	  
	sed -i 's/#set_var EASYRSA_KEY_SIZE	2048/set_var EASYRSA_KEY_SIZE   '$KEYSIZE'/' vars #change key size to desired size
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full "$CLIENT" nopass
	./easyrsa gen-crl
   
	openvpn --genkey --secret /etc/openvpn/easy-rsa/pki/private/ta.key    #generate TLS key for additional security
	
     
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn
	if [ "$UDP" = 1 ]; then
	# Generate udp.conf
		echo "port $PORT
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
push \"register-dns\"
topology subnet
server 10.8.0.0 255.255.255.0
cipher $CIPHER
auth $DIGEST
ifconfig-pool-persist ipp.txt" > /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		if [ $TLS = 1 ]; then
			echo "--tls-auth /etc/openvpn/easy-rsa/pki/private/ta.key 0" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf #TLS key information added to config file
		fi
	# DNS
		case $DNS in
			1) 
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			done
			;;
			2)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			3) 
			echo 'push "dhcp-option DNS 4.2.2.2"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 4.2.2.4"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			4) 
			echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			5) 
			echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			6) 
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			7)
			echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		esac
		echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		if [ "$INTERNALNETWORK" = 1 ]; then
			echo "client-to-client" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		fi
	fi 
	
	if [ "$TCP" = 1 ]; then
		echo "port $PORTTCP
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
push \"register-dns\"
topology subnet
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
cipher $CIPHER
auth $DIGEST
sndbuf 0
rcvbuf 0" > /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
	
		if [ $TLS = 1 ]; then
			echo "--tls-auth /etc/openvpn/easy-rsa/pki/private/ta.key 0" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf #TLS key information added to config file
		fi	
	# DNS
		case $DNS in
			1) 
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			done
			;;
			2)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			3) 
			echo 'push "dhcp-option DNS 4.2.2.2"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 4.2.2.4"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			4) 
			echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			5) 
			echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			6) 
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			7)
			echo 'push "dhcp-option DNS 10.9.0.1"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		esac
		echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		if [ "$INTERNALNETWORK" = 1 ]; then
			echo "client-to-client" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		fi
	fi

	# Enable net.ipv4.ip_forward for the system
	sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	sed -i " 5 a\echo 1 > /proc/sys/net/ipv4/ip_forward" $RCLOCAL    # Added for servers that don't read from sysctl at startup
	
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set NAT for the VPN subnet
	   if [ "$INTERNALNETWORK" = 1 ]; then
	    if [ "$UDP" = 1 ]; then
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP     
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
		if [ "$TCP" = 1 ]; then
			iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $IP
			sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
	   else
	   if [ "$UDP" = 1 ]; then
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.1 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
		if [ "$TCP" = 1 ]; then
			iptables -t nat -A POSTROUTING -s 10.9.0.0/24  ! -d 10.9.0.1 -j SNAT --to $IP #This line and the next one are added for tcp server instance
			sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -j SNAT --to $IP" $RCLOCAL
		fi
	   fi
	
	if iptables -L | grep -q REJECT; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		if [ "$UDP" = 1 ]; then
		iptables -I INPUT -p udp --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
		if [ "$TCP" = 1 ]; then
			iptables -I INPUT -p udp --dport $PORTTCP -j ACCEPT #This line and next 5 lines have been added for tcp support
			iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p tcp --dport $PORTTCP -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	###############################################################################################################
	# START_SERVICE_SECTION
	# Install and start service for both UDP and TCP
	###############################################################################################################
	if [ "$UDP" = 1 ]; then
		echo "[Unit]
#Created by openvpn-install-advanced (https://github.com/pl48415/openvpn-install-advanced)
Description=OpenVPN Robust And Highly Flexible Tunneling Application On <server>
After=syslog.target network.target

[Service]
Type=forking
PIDFile=/var/run/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.pid
ExecStart=/usr/sbin/openvpn --daemon --writepid /var/run/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.pid --cd /etc/openvpn/ --config $UDP_SERVICE_AND_CONFIG_NAME.conf

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/$UDP_SERVICE_AND_CONFIG_NAME.service
		if pgrep systemd-journal; then
			sudo systemctl enable $UDP_SERVICE_AND_CONFIG_NAME.service
		fi
	fi

	if [ "$TCP" = 1 ]; then
		echo "[Unit]
#Created by openvpn-install-advanced (https://github.com/pl48415/openvpn-install-advanced)
Description=OpenVPN Robust And Highly Flexible Tunneling Application On <server>
After=syslog.target network.target

[Service]
Type=forking
PIDFile=/var/run/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.pid
ExecStart=/usr/sbin/openvpn --daemon --writepid /var/run/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.pid --cd /etc/openvpn/ --config $TCP_SERVICE_AND_CONFIG_NAME.conf

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/$TCP_SERVICE_AND_CONFIG_NAME.service
		if pgrep systemd-journal; then
			sudo systemctl enable $TCP_SERVICE_AND_CONFIG_NAME.service
		fi
	fi
	
	if pgrep systemd-journal; then
		sudo systemctl start openvpn.service
	else
		if [[ "$OS" = 'debian' ]]; then
			/etc/init.d/openvpn start
		else
			service openvpn start
		fi
	fi
	
	###############################################################################################################
	# END_SERVICE_SECTION
	###############################################################################################################

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit or Scaleway users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (LowEndSpirit or Scaleway), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further UDP users later
	if [ "$UDP" = 1 ]; then
	echo "client
dev tun
cipher $CIPHER
auth $DIGEST
proto udp
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3" > /etc/openvpn/client-common.txt
newclient "$CLIENT"
  fi
    if [ "$TCP" = 1 ]; then
	echo "client  
	cipher $CIPHER
auth $DIGEST
dev tun
proto tcp
remote $IP $PORTTCP
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
sndbuf 0
rcvbuf 0
" > /etc/openvpn/clienttcp-common.txt  # clienttcp-common.txt is created so we have a template to add further TCP users later
newclienttcp "$CLIENT"
	fi
	# Generates the custom client.ovpn
	
	
	
	echo ""
	echo "Finished!"
	echo ""
	if [ "$UDP" = 1 ]; then
	echo "Your UDP client config is available at ~/$CLIENT.ovpn"
	fi
	if [ "$TCP" = 1 ]; then
	echo "Your TCP client config is available at ~/${CLIENT}tcp.ovpn"
	fi
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
if [ "$DNSRESOLVER" = 1 ]; then 
sudo service bind9 restart
fi
