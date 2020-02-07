#!/bin/bash

set -o pipefail

script_name=`basename "$0"`
script_abs_name=`readlink -f "$0"`
script_path=`dirname "$script_abs_name"`

# check root
if [ `id -u` != '0' ]
then
    echo "error: must run by root"
    exit 1
fi

# check nginx
which nginx >/dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "error: nginx not installed"
    exit 1
fi

# check php
which php >/dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "error: php not installed"
    exit 1
fi

# get domain
if [ ! -f "$script_path"/domain.txt ]
then
    echo "error: can not find domain.txt, please put your domain in domain.txt"
    exit 1
fi

domain_list=`cat "$script_path"/domain.txt`
if [ $? -ne 0 ]; then exit 1; fi

# check 80 port
(echo >/dev/tcp/localhost/80) >/dev/null 2>&1
if [ $? -eq 0 ]
then
    echo "error: 80 port is in use, please shutdown your system nginx first"
    exit 1
fi

# search openssl.cnf
openssl_cnf_file_list="
/etc/ssl/openssl.cnf
/etc/pki/tls/openssl.cnf"

for file in $openssl_cnf_file_list
do
    if [ -f "$file" ]
    then
        openssl_cnf_file=$file
        break
    fi
done

if [ -z "$openssl_cnf_file" ]
then
    echo "can not find openssl.cnf"
    exit 1
fi

# create work dir
mkdir -p "$script_path"/work
if [ $? -ne 0 ]; then exit 1; fi
mkdir -p "$script_path"/work/acme-challenge
if [ $? -ne 0 ]; then exit 1; fi
mkdir -p "$script_path"/work/log
if [ $? -ne 0 ]; then exit 1; fi
mkdir -p "$script_path"/work/tmp
if [ $? -ne 0 ]; then exit 1; fi
mkdir -p "$script_path"/cert
if [ $? -ne 0 ]; then exit 1; fi

# generate account private key
if [ ! -f "$script_path"/cert/account.key ]
then
    openssl genrsa -out "$script_path"/cert/account.key 4096 >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        echo "error: generate account private key failed"
        exit 1
    fi
fi

# generate domain private key
if [ ! -f "$script_path"/cert/ssl.key ]
then
    openssl genrsa -out "$script_path"/cert/ssl.key 2048 >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        echo "error: generate domain private key failed"
        exit 1
    fi
fi

# generate csr from domain private key
if [ ! -f "$script_path"/cert/domain.csr ]
then
    for domain in $domain_list
    do
        alt_name="$alt_name""DNS:$domain,"
    done

    cp "$openssl_cnf_file" "$script_path"/cert/domain.conf
    if [ $? -ne 0 ]; then exit 1; fi
    printf "[SAN]\nsubjectAltName=" >> "$script_path"/cert/domain.conf
    if [ $? -ne 0 ]; then exit 1; fi
    printf "$alt_name" | sed 's/,$//g' >> "$script_path"/cert/domain.conf
    if [ $? -ne 0 ]; then exit 1; fi

    openssl req -new -sha256 \
                -key cert/ssl.key \
                -out "$script_path"/cert/domain.csr \
                -subj "/" -reqexts SAN \
                -config "$script_path"/cert/domain.conf
    if [ $? -ne 0 ]; then exit 1; fi
fi

# start cert-nginx process
bash "$script_path"/cert-nginx.init start
# setup cleanup function
do_cleanup() {
    bash "$script_path"/cert-nginx.init stop
}
trap do_cleanup EXIT

# get cert
echo "[getting cert from Let's Encrypt][may be serveral minutes]"
for domain in $domain_list
do
    domain_param="$domain_param""$domain;"
done
domain_param=`printf "$domain_param" | sed 's/;$//g'`
if [ $? -ne 0 ]; then exit 1; fi

php "$script_path"/acme-v2-client.php \
    -a "$script_path"/cert/account.key \
    -r "$script_path"/cert/domain.csr \
    -d "$domain_param" \
    -c "$script_path"/work/acme-challenge \
    -o "$script_path"/cert/ssl.crt.new
if [ $? -ne 0 ]; then exit 1; fi

cp "$script_path"/cert/ssl.crt.new \
   "$script_path"/cert/ssl.crt
if [ $? -ne 0 ]; then exit 1; fi

find "$script_path"/work/acme-challenge -type f -delete
if [ $? -ne 0 ]; then exit 1; fi

exit 0
