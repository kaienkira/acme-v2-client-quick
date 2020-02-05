#!/usr/bin/env php
<?php

class Config
{
    // debug use
    public static $acme_url_base = 'https://acme-staging-v02.api.letsencrypt.org';
    // prod use
    // public static $acme_url_base = 'https://acme-v02.api.letsencrypt.org';
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

function urlbase64($bin)
{
    return str_replace(
        array('+', '/', '='),
        array('-', '_', ''),
        base64_encode($bin));
}

function loadAccountKey($account_key_file)
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

function loadCsrFile($csr_file)
{
    $csr_file_content = file_get_contents($csr_file);
    if ($csr_file_content === false) {
        echo "can not open file: $csr_file_content\n";
        return false;
    }
    $lines = explode("\n", $csr_file_content);
    unset($lines[0]);
    unset($lines[count($lines) - 1]);
    return urlbase64(base64_decode(implode('', $lines)));
}

function getRsaKeyInfo($key)
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
        'e' => urlbase64($key_info['rsa']['e']),
        'n' => urlbase64($key_info['rsa']['n']),
    );
}

function signMessage($key, $message)
{
    if (openssl_sign($message, $sign, $key, 'sha256') === false) {
        return false;
    }

    return urlbase64($sign);
}

function httpRequest($url, $method, $post_data = '')
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

function getReplayNonce($acme_res, $http_response_header)
{
    preg_match('/^[Rr]eplay-[Nn]once: (.*?)\r\n/sm',
        $http_response_header, $matches);
    if (isset($matches[1]) === false) {
        echo "curl failed: replay nonce header is missing\n";
        return false;
    }
    $acme_res['nonce'] = $matches[1];

    return true;
}

function signedHttpRequest($acme_res, $url, $payload)
{
    // get first nonce
    if ($acme_res['nonce'] == '') {
        $ret = httpRequest($acme_res['new_nonce'], 'head');
        if ($ret === false) {
            return false;
        }
        if (getReplayNonce($acme_res, $ret['header']) === false) {
            return false;
        }
    }
}

function buildAcmeResource($account_key)
{
    $ret = httpRequest(Config::$acme_url_base.'/directory', 'get');
    if ($ret === false) {
        return false;
    }

    $response = json_decode($ret['response'], true);
    if ($response === false) {
        echo 'acme/directory failed: invalid response'."\n";
        return false;
    }

    $acme_res = array();

    if (isset($response['newNonce']) === false) {
        echo 'acme/directory failed: `newNonce` not found'."\n";
        return false;
    }
    $acme_res['new_nonce'] = $response['newNonce'];

    if (isset($response['newAccount']) === false) {
        echo 'acme/directory failed: `newAccount` not found'."\n";
        return false;
    }
    $acme_res['new_account'] = $response['newAccount'];

    if (isset($response['newOrder']) === false) {
        echo 'acme/directory failed: `newOrder` not found'."\n";
        return false;
    }
    $acme_res['new_order'] = $response['newOrder'];

    if (isset($response['meta']) === false ||
        isset($response['meta']['termsOfService']) === false) {
        echo 'acme/directory failed: `meta/termsOfService` not found'."\n";
        return false;
    }
    $acme_res['tos'] = $response['meta']['termsOfService'];
    $acme_res['nonce'] = '';

    $account_key_info = getRsaKeyInfo($account_key);
    if ($account_key_info === false) {
        return false;
    }
    $acme_res['account_key_info'] = $account_key_info;

    return $acme_res;
}

function registerAccount($acme_res)
{
    // register account
    $ret = signedHttpRequest($acme_res, $acme_res['new_account'], array(
        'termsOfServiceAgreed' => true,
    ));

    return true;
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
    $account_key = loadAccountKey($account_key_file);
    if ($account_key === false) {
        return false;
    }

    // load csr file
    $csr = loadCsrFile($csr_file);
    if ($csr === false) {
        return false;
    }

    // build acme resource
    $acme_res = buildAcmeResource($account_key);
    if ($acme_res === false) {
        return false;
    }

    // check tos
    if ($tos != '' && $tos != $acme_res['tos']) {
        echo "terms of service has changed: ".
             "please modify your -t command option\n".
             'new tos: '.$acme_res['tos']."\n";
        return false;
    }

    // register account
    if (registerAccount($acme_res) === false) {
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
