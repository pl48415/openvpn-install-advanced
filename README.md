# openvpn-install-advanced
This script is based upon [Nyr's](https://github.com/Nyr/) OpenVPN [roadwarrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29) installer.

I have added additional options for improved security and compatibility with restricted networks.

You can choose between 2048bit or 4096bit RSA key.

Generating 4096bit Diffie-Hellman parameters can take few hours if you have a really slow machine. 

Available symmetrical ciphers are: 

                                   AES-256-CBC
                                   AES-128-CBC
                                   BF-CBC
                                   CAMELLIA-256-CBC
                                   CAMELLIA-128-CBC
You can choose between 256bit or 512bit SHA2 digest.

You can choose whether or not use a static preshared key for an additional layer of security.

You can create UDP or TCP server or both of them and choose a port for each of them.
Before choosing TCP to be installed please look at http://sites.inka.de/bigred/devel/tcp-tcp.html to understand the implications

You can create personal DNS resolver that is accessible only through vpn so you can tunnel even DNS requests.

Using TCP server with port 443 can bypass some network firewalls that block OpenVPN traffic.

Added an option to force all unencrypted traffic go through privoxy+HAVP+ClamAV.
Privoxy is used for increased privacy and ad blocking. After privoxy all traffic goes to
HAVP and is scanned with ClamAV. It is recommended to use system with at least 1GB of ram for these features.

# Installation
`wget https://git.io/vcIGP -O openvpn-install-advanced.sh && bash openvpn-install-advanced.sh`

This script has been tested on 

    - Debian 7
    - Debian 8
    - Ubuntu 14
