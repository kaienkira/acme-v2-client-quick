#!/usr/bin/env php
<?php

final class Config
{
    // dev use
    // public static $acme_url_base = 'https://acme-staging-v02.api.letsencrypt.org';
    // prod use
    public static $acme_url_base = 'https://acme-v02.api.letsencrypt.org';
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
    private $csr_ = null;
    private $nonce_ = null;
    private $kid_ = null;

    private $new_nonce_url_ = null;
    private $new_account_url_ = null;
    private $new_order_url_ = null;
    private $tos_url_ = null;

    public function init($account_key_file, $csr_file)
    {
        if ($this->initAccountKey($account_key_file) === false) {
            return false;
        }
        if ($this->initCsr($csr_file) === false) {
            return false;
        }
        if ($this->initAcmeDirectory() === false) {
            return false;
        }

        return true;
    }

    private function initAccountKey($account_key_file)
    {
        $key_file_content = file_get_contents($account_key_file);
        if ($key_file_content === false) {
            echo "can not open file: $account_key_file\n";
            return false;
        }

        $this->account_key_ = openssl_pkey_get_private($key_file_content);
        if ($this->account_key_ === false) {
            echo "openssl failed: ".openssl_error_string()."\n";
            return false;
        }

        $key_info = openssl_pkey_get_details($this->account_key_);
        if ($key_info === false) {
            echo "openssl failed: ".openssl_error_string()."\n";
            return false;
        }
        if (isset($key_info['rsa']) === false) {
            echo 'account key file is not rsa private key'."\n";
            return false;
        }

        $e = Util::urlbase64($key_info['rsa']['e']);
        $n = Util::urlbase64($key_info['rsa']['n']);
        $thumb_print = array(
            'e' => $e,
            'kty' => 'RSA',
            'n' => $n,
        );
        $thumb_print = Util::urlbase64(openssl_digest(
            json_encode($thumb_print), 'sha256', true));

        $this->account_key_info_ = array(
            'e' => $e,
            'n' => $n,
            'thumb_print' => $thumb_print,
        );
    }

    private function initCsr($csr_file)
    {
        $csr_file_content = file_get_contents($csr_file);
        if ($csr_file_content === false) {
            echo "can not open file: $csr_file_content\n";
            return false;
        }
        $lines = explode("\n", $csr_file_content);
        unset($lines[0]);
        unset($lines[count($lines) - 1]);
        $this->csr_ = Util::urlbase64(base64_decode(implode('', $lines)));

        return true;
    }

    private function initAcmeDirectory()
    {
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

    public function createAccount()
    {
        // create account
        $ret = self::signedHttpRequest($this->new_account_url_, array(
            'termsOfServiceAgreed' => true,
        ));
        if ($ret === false) {
            return false;
        }
        // 200 - account exists
        // 201 - account created
        if ($ret['http_code'] != 200 &&
            $ret['http_code'] != 201) {
            echo 'acme/newAccount failed: '.$ret['response']."\n";
            return false;
        }

        if (self::fetchKeyId($ret['header']) === false) {
            return false;
        }

        return true;
    }

    public function issueCertificate(
        $domain_list, $http_challenge_dir, $output_cert_file)
    {
        $identifiers = array();
        foreach ($domain_list as $domain) {
            array_push($identifiers, array(
                'type' => 'dns',
                'value' => $domain,
            ));
        }

        // submit order
        $ret = self::signedHttpRequest($this->new_order_url_, array(
            'identifiers' => $identifiers,
        ));
        if ($ret === false) {
            return false;
        }
        // 201 - order created
        if ($ret['http_code'] != 201) {
            echo 'acme/newOrder failed: '.$ret['response']."\n";
            return false;
        }

        $response = json_decode($ret['response'], true);
        if ($response === false) {
            echo 'acme/newOrder failed: invalid response'."\n";
            return false;
        }
        if (isset($response['authorizations']) === false) {
            echo 'acme/newOrder failed: `authorizations` not found'."\n";
            return false;
        }
        if (is_array($response['authorizations']) === false) {
            echo 'acme/newOrder failed: `authorizations` is invalid'."\n";
            return false;
        }
        if (isset($response['finalize']) === false) {
            echo 'acme/newOrder failed: `finalize` not found'."\n";
            return false;
        }

        $authorization_urls = $response['authorizations'];
        $order_finalize_url = $response['finalize'];

        foreach ($authorization_urls as $authorization_url) {
            $ret = self::signedHttpRequest($authorization_url, '');
            if ($ret === false) {
                return false;
            }
            if ($ret['http_code'] != 200) {
                echo 'acme/authorization failed: '.$ret['response']."\n";
                return false;
            }

            $response = json_decode($ret['response'], true);
            if ($response === false) {
                echo 'acme/authorization failed: invalid response'."\n";
                return false;
            }
            if (isset($response['challenges']) === false) {
                echo 'acme/authorization failed: `challenges` not found'."\n";
                return false;
            }
            if (is_array($response['challenges']) === false) {
                echo 'acme/authorization failed: `challenges` is invalid'."\n";
                return false;
            }

            $challenges = $response['challenges'];

            $http_challenge = null;
            foreach ($challenges as $challenge) {
                if (isset($challenge['type']) &&
                    isset($challenge['url']) &&
                    isset($challenge['token']) &&
                    $challenge['type'] === 'http-01') {
                    $http_challenge = $challenge;
                }
            }
            if ($http_challenge === null) {
                echo 'acme/authorization failed: `challenges` is invalid'."\n";
                return false;
            }

            // write challenge file
            $challenge_file_path =
                $http_challenge_dir.'/'.$http_challenge['token'];
            $challenge_file_content = $http_challenge['token'].'.'
                .$this->account_key_info_['thumb_print'];
            if (file_put_contents($challenge_file_path,
                    $challenge_file_content) === false) {
                return false;
            }

            // send challenge ready
            $ret = self::signedHttpRequest($http_challenge['url'], '{}');
            if ($ret === false) {
                return false;
            }
            if ($ret['http_code'] != 200) {
                echo 'acme/challenge failed: '.$ret['response']."\n";
                return false;
            }

            // wait to be verified
            for (;;) {
                $ret = self::signedHttpRequest($authorization_url, '');
                if ($ret === false) {
                    return false;
                }
                if ($ret['http_code'] != 200) {
                    echo 'acme/authorization failed: '.$ret['response']."\n";
                    return false;
                }

                $response = json_decode($ret['response'], true);
                if ($response === false) {
                    echo 'acme/authorization failed: invalid response'."\n";
                    return false;
                }
                if (isset($response['status']) === false) {
                    echo 'acme/authorization failed: `status` not found'."\n";
                    return false;
                }
                if ($response['status'] === 'invalid') {
                    echo 'acme/authorization failed: '.$ret['response']."\n";
                    return false;
                } else if ($response['status'] === 'pending') {
                    sleep(2);
                    continue;
                } else if ($response['status'] === 'valid') {
                    break;
                } else {
                    echo 'acme/authorization failed: `status` is invalid'."\n";
                    return false;
                }
            }
        }

        // finalize order
        $certificate_url = null;
        for (;;) {
            $ret = self::signedHttpRequest($order_finalize_url, array(
                'csr' => $this->csr_,
            ));
            if ($ret === false) {
                return false;
            }
            if ($ret['http_code'] != 200) {
                echo 'acme/finalizeOrder failed: '.$ret['response']."\n";
                return false;
            }

            $response = json_decode($ret['response'], true);
            if ($response === false) {
                echo 'acme/finalizeOrder failed: invalid response'."\n";
                return false;
            }
            if (isset($response['status']) === false) {
                echo 'acme/finalizeOrder failed: `status` not found'."\n";
                return false;
            }

            if ($response['status'] === 'processing') {
                sleep(2);
                continue;
            } else if ($response['status'] === 'valid') {
                if (isset($response['certificate']) === false) {
                    echo 'acme/finalizeOrder failed: '.
                        '`certificate` not found'."\n";
                    return false;
                }
                $certificate_url = $response['certificate'];
                break;
            } else {
                echo 'acme/finalizeOrder failed: '.$ret['response']."\n";
                return false;
            }
        }

        // download certificate
        $ret = self::signedHttpRequest($certificate_url, '');
        if ($ret === false) {
            return false;
        }
        if ($ret['http_code'] != 200) {
            echo 'acme/certificate failed: '.$ret['response']."\n";
            return false;
        }
        if (file_put_contents(
                $output_cert_file, $ret['response']) === false) {
            return false;
        }

        return true;
    }

    private function fetchReplayNonce($http_response_header)
    {
        preg_match('/^[Rr]eplay-[Nn]once: (.*?)\r\n/sm',
            $http_response_header, $matches);
        if (isset($matches[1]) === false) {
            echo "acme failed: replay-nonce header is missing\n";
            return false;
        }
        $this->nonce_ = $matches[1];

        return true;
    }

    private function fetchKeyId($http_response_header)
    {
        preg_match('/^[Ll]ocation: (.*?)\r\n/sm',
            $http_response_header, $matches);
        if (isset($matches[1]) === false) {
            echo "acme failed: location header(kid) is missing\n";
            return false;
        }
        $this->kid_ = $matches[1];
    }

    private function signMessage($message)
    {
        if (openssl_sign($message, $sign,
                $this->account_key_, 'sha256') === false) {
            echo "openssl failed: ".openssl_error_string()."\n";
            return false;
        }

        return Util::urlbase64($sign);
    }

    private function signedHttpRequest($url, $payload)
    {
        // get first nonce
        if ($this->nonce_ === null) {
            $ret = Util::httpRequest($this->new_nonce_url_, 'head');
            if ($ret === false) {
                return false;
            }
            if (self::fetchReplayNonce($ret['header']) === false) {
                return false;
            }
        }

        // protected
        $protected = array(
            'alg' => 'RS256',
            'nonce' => $this->nonce_,
            'url' => $url,
        );

        if ($this->kid_ === null) {
            $protected['jwk'] = array(
                'kty' => 'RSA',
                'e' => $this->account_key_info_['e'],
                'n' => $this->account_key_info_['n'],
            );
        } else {
            $protected['kid'] = $this->kid_;
        }

        $protected64 =
            Util::urlbase64(json_encode($protected));
        $payload64 = is_string($payload)
            ? Util::urlbase64($payload)
            : Util::urlbase64(json_encode($payload));
        $sign = self::signMessage($protected64.'.'.$payload64);
        if ($sign === false) {
            return false;
        }

        $request_data = array(
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $sign,
        );
        $request_data = json_encode($request_data);

        $ret = Util::httpRequest($url, 'post', $request_data, array(
            'Content-Type: application/jose+json',
        ));

        // update nonce
        if ($ret !== false && isset($ret['header'])) {
            if (self::fetchReplayNonce($ret['header']) === false) {
                return false;
            }
        }

        return $ret;
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

    // create acme client
    $acme_client = new AcmeClient();
    if ($acme_client->init(
            $account_key_file, $csr_file) === false) {
        return false;
    }
    // check tos
    if ($acme_client->checkTermOfService($tos) === false) {
        return false;
    }
    // create account
    if ($acme_client->createAccount() === false) {
        return false;
    }
    // issue certificate
    if ($acme_client->issueCertificate($domain_list,
            $http_challenge_dir, $output_cert_file) === false) {
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
