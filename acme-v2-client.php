#!/usr/bin/env php
<?php

final class Config
{
    // debug use
    public static $acme_url_base = 'https://acme-staging-v02.api.letsencrypt.org';
    // prod use
    // public static $acme_url_base = 'https://acme-v02.api.letsencrypt.org';
}

final class Util
{
    public static function urlbase64($bin)
    {
        return str_replace(
            array('+', '/', '='),
            array('-', '_', ''),
            base64_encode($bin));
    }

    public static function signMessage($key, $message)
    {
        if (openssl_sign($message, $sign, $key, 'sha256') === false) {
            return false;
        }

        return self::urlbase64($sign);
    }

    public static function getRsaKeyInfo($key)
    {
        $key_info = openssl_pkey_get_details($key);
        if ($key_info === false) {
            echo "openssl failed: ".openssl_error_string()."\n";
            return false;
        }
        if (!isset($key_info['rsa'])) {
            echo "account key file is not rsa private key\n";
            return false;
        }

        return array(
            'e' => self::urlbase64($key_info['rsa']['e']),
            'n' => self::urlbase64($key_info['rsa']['n']),
        );
    }

    public static function loadAccountKey($account_key_file)
    {
        $key_file_content = file_get_contents($account_key_file);
        if ($key_file_content === false) {
            echo "can not open file: $account_key_file\n";
            return false;
        }
        $key = openssl_pkey_get_private($key_file_content);
        if ($key === false) {
            echo "openssl failed: ".openssl_error_string()."\n";
            return false;
        }

        return $key;
    }

    public static function loadCsrFile($csr_file)
    {
        $csr_file_content = file_get_contents($csr_file);
        if ($csr_file_content === false) {
            echo "can not open file: $csr_file_content\n";
            return false;
        }
        $lines = explode("\n", $csr_file_content);
        unset($lines[0]);
        unset($lines[count($lines) - 1]);
        return self::urlbase64(base64_decode(implode('', $lines)));
    }

    public static function httpRequest($url, $method,
        $post_data = '', $request_headers = [])
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);

        $method = strtolower($method);
        if ($method === 'head') {
            // head method
            curl_setopt($ch, CURLOPT_NOBODY, true);
        } else if ($method === 'get') {
            // get method
        } else if ($method === 'post') {
            // post method
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        } else {
            echo "curl failed: invalid http method\n";
            return false;
        }

        if (count($request_headers) > 0) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $request_headers);
        }

        $output = curl_exec($ch);
        if ($output === false) {
            echo 'curl failed: '.curl_error($ch)."\n";
            return false;
        }
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($output, 0, $header_size);
        $response = substr($output, $header_size);

        curl_close($ch);

        return array(
            'http_code' => $http_code,
            'header' => $header,
            'response' => $response,
        );
    }
}

final class AcmeClient
{
    private $account_key_ = null;
    private $account_key_info_ = null;
    private $nonce_ = null;

    private $new_nonce_url_ = null;
    private $new_account_url_ = null;
    private $new_order_url_ = null;
    private $tos_url_ = null;

    public function init($account_key)
    {
        $this->account_key_ = $account_key;

        $account_key_info = Util::getRsaKeyInfo($account_key);
        if ($account_key_info === false) {
            return false;
        }
        $this->account_key_info_ = $account_key_info;

        $ret = Util::httpRequest(Config::$acme_url_base.'/directory', 'get');
        if ($ret === false) {
            return false;
        }

        $response = json_decode($ret['response'], true);
        if ($response === false) {
            echo 'acme/directory failed: invalid response'."\n";
            return false;
        }

        if (isset($response['newNonce']) === false) {
            echo 'acme/directory failed: `newNonce` not found'."\n";
            return false;
        }
        $this->new_nonce_url_ = $response['newNonce'];

        if (isset($response['newAccount']) === false) {
            echo 'acme/directory failed: `newAccount` not found'."\n";
            return false;
        }
        $this->new_account_url_ = $response['newAccount'];

        if (isset($response['newOrder']) === false) {
            echo 'acme/directory failed: `newOrder` not found'."\n";
            return false;
        }
        $this->new_order_url_ = $response['newOrder'];

        if (isset($response['meta']) === false ||
            isset($response['meta']['termsOfService']) === false) {
            echo 'acme/directory failed: `meta/termsOfService` not found'."\n";
            return false;
        }
        $this->tos_url_ = $response['meta']['termsOfService'];

        return true;
    }

    public function checkTermOfService($tos)
    {
        if ($tos != '' && $tos != $this->tos_url_) {
            echo "terms of service has changed: ".
                 "please modify your -t command option\n".
                 'new tos: '.$this->tos_url_."\n";
            return false;
        }

        return true;
    }

    public function registerAccount()
    {
        // register account
        $ret = self::signedHttpRequest($this->new_account_url_, array(
            'termsOfServiceAgreed' => true,
        ));

        return true;
    }

    private function getReplayNonce($http_response_header)
    {
        preg_match('/^[Rr]eplay-[Nn]once: (.*?)\r\n/sm',
            $http_response_header, $matches);
        if (isset($matches[1]) === false) {
            echo "curl failed: replay nonce header is missing\n";
            return false;
        }
        $this->nonce_ = $matches[1];

        return true;
    }

    private function signedHttpRequest($url, $payload)
    {
        // get first nonce
        if ($this->nonce_ === null) {
            $ret = Util::httpRequest($this->new_nonce_url_, 'head');
            if ($ret === false) {
                return false;
            }
            if (self::getReplayNonce($ret['header']) === false) {
                return false;
            }
        }

        // protected
        $protected = array(
            'alg' => 'RS256',
            'jwk' => array(
                'kty' => 'RSA',
                'e' => $this->account_key_info_['e'],
                'n' => $this->account_key_info_['n'],
            ),
            'nonce' => $this->nonce_,
            'url' => $url,
        );

        $payload64 = Util::urlbase64(json_encode($payload));
        $protected64 = Util::urlbase64(json_encode($protected));
        $sign = Util::signMessage(
            $this->account_key_, $protected64.'.'.$payload64);
        if ($sign === false) {
            return false;
        }

        $request_data = array(
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $sign,
        );
        $request_data = json_encode($request_data);

        return Util::httpRequest($url, 'post', $request_data, array(
            'Content-Type: application/jose+json',
        ));
    }
}

function printUsage($prog_name)
{
    echo "usage: $prog_name ".
         '-a <account_key_file> '.
         '-r <csr_file> '.
         '-d <domain_list(domain1;domain2...;domainN)> '.
         '-c <http_challenge_dir> '.
         '-o <output_cert_file>'.
         '[-t <terms_of_service>]'.
         "\n";
}

function main($argc, $argv)
{
    $prog_name = basename($argv[0]);
    $cmd_options = getopt('a:r:d:c:o:t:');
    if (!isset($cmd_options['a']) ||
        !isset($cmd_options['r']) ||
        !isset($cmd_options['d']) ||
        !isset($cmd_options['c']) ||
        !isset($cmd_options['o'])) {
        printUsage($prog_name);
        return false;
    }

    $account_key_file = $cmd_options['a'];
    $csr_file = $cmd_options['r'];
    $domain_list = explode(";", $cmd_options['d']);
    $http_challenge_dir = $cmd_options['c'];
    $output_cert_file = $cmd_options['o'];
    $tos = isset($cmd_options['t']) ? $cmd_options['t'] : '';

    // load account key
    $account_key = Util::loadAccountKey($account_key_file);
    if ($account_key === false) {
        return false;
    }
    // load csr file
    $csr = Util::loadCsrFile($csr_file);
    if ($csr === false) {
        return false;
    }

    // create acme client
    $acme_client = new AcmeClient();
    if ($acme_client->init($account_key) === false) {
        return false;
    }
    // check tos
    if ($acme_client->checkTermOfService($tos) === false) {
        return false;
    }
    // register account
    if ($acme_client->registerAccount() === false) {
        return false;
    }

    return true;
}

if (PHP_SAPI !== 'cli') {
    exit(1);
}
if (main($argc, $argv) === false) {
    exit(1);
}
exit(0);
