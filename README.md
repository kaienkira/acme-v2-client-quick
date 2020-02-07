# acme-v2-client-quick
Get Let's Encrypt Cert In Five Minutes (Support ACME v2)

* Support ACME v2 (RFC 8555), ACME v1 is deprecated
* It's a Quick and Dirty method, For security and detail guide please READ
  https://github.com/kaienkira/acme-v2-client

# Steps
# get dependency
```
# ArchLinux
pacman -S php nginx

# CentOS
yum install php-cli php-curl nginx

# Ubuntu
sudo apt-get install php-cli php-curl nginx
```

## put your domain name in domain.txt
```
cd acme-v2-client-quick
echo "example.com" >> domain.txt
echo "www.example.com" >> domain.txt
```

## get cert
```
# need root because http-01 challenge need listen 80 port
# make sure your system 80 port is free
# maybe you need run
# sudo systemctl stop nginx first
sudo ./quick-start.sh
```

## result file
```
cd cert

# ssl.key -- your domain private key
# ssl.crt -- your domain cert

# nginx config
# ...
# ssl_certificate /path/to/ssl.crt;
# ssl_certificate_key /path/to/ssl.key;
# ...
```
