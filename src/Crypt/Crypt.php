<?php

namespace RudyMas\Crypt;

use phpseclib\Crypt\AES;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\Random;
use phpseclib\Crypt\RSA;
use RudyMas\Manipulator\Text;

/**
 * Class Crypt - A wrapper for phpseclib (Cryptography)
 *
 * This class is used in combination with following class:
 *    - phpseclib (composer install phpseclib/phpseclib)
 *    - manipulator/text (composer install rudymas/manipulator)
 *
 * @author      Rudy Mas <rudy.mas@rmsoft.be>
 * @copyright   Copyright (c) 2016, rudymas.be. (http://www.rmsoft.be/)
 * @license     https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version     0.6.0
 * @package     RudyMas\Crypt
 */
class Crypt
{
    private $key;
    private $iv;
    private $hash;

    /**
     * To encrypt data with a certain type (AES, DES, ...)
     * $key, $iv and $hash information are saved
     *
     * @param string $cryptType The method to use for encryption
     * @param string $data The data to encrypt
     * @return string               The encrypted data
     */
    public function encrypt($cryptType, $data)
    {
        switch (strtoupper($cryptType)) {
            case 'DES':
                $cipher = new DES();
                $text = new Text();
                $random = new Random();

                // Create and store the DES key
                $this->setKey($text->randomText(8));
                $cipher->setKey($this->getKey());
                // Create and store the IV
                $this->setIv($random->string($cipher->getBlockLength() >> 3));
                $cipher->setIV($this->getIv());
                // Store the hash of the file data
                $this->setHash(sha1($data));
                // Encrypt the data and return it as a string
                return $cipher->encrypt($data);
                break;
            case 'AES':
                $cipher = new AES();
                $text = new Text();
                $random = new Random();

                // Create and store the AES key
                $this->setKey($text->randomText(32));
                $cipher->setKey($this->getKey());
                // Create and store the IV
                $this->setIv($random->string($cipher->getBlockLength() >> 3));
                $cipher->setIV($this->getIv());
                // Store the hash of the file data
                $this->setHash(sha1($data));
                // Encrypt the data and return it as a string
                return $cipher->encrypt($data);
                break;
            case 'RSA':
                $rsa = new RSA();

                // Load the RSA key outside this class through $crypt->setKey('...');
                $rsa->loadKey($this->getKey());
                // Encrypt the data and return it as a string
                return $rsa->encrypt($data);
                break;
            default:
                die("Cryptography for '$cryptType' not implemented yet!");
        }
    }

    /**
     * To decrypt data with a certain type (AES, DES, ...)
     * $key, $iv and $hash information are saved
     *
     * @param string $cryptType The Method of decryption to use
     * @param string $data The date to decrypt
     * @return string The decrypted data
     */
    public function decrypt($cryptType, $data)
    {
        switch (strtoupper($cryptType)) {
            case 'DES':
                $cipher = new DES();

                // Load the DES key
                $cipher->setKey($this->getKey());
                // Load the IV
                $cipher->setIV($this->getIv());
                // Decrypt the data
                $decrypt = $cipher->decrypt($data);
                // Store the hash of the file data
                $this->setHash(sha1($decrypt));
                // Return the decrypted data
                return $decrypt;
                break;
            case 'AES':
                $cipher = new AES();

                // Load the AES key
                $cipher->setKey($this->getKey());
                // Load the IV
                $cipher->setIV($this->getIv());
                // Encrypt the data and return it as a string
                $decrypt = $cipher->decrypt($data);
                // Store the hash of the file data
                $this->setHash(sha1($decrypt));
                // Return the decrypted data
                return $decrypt;
                break;
            case 'RSA':
                $rsa = new RSA();

                // Load the RSA key outside this class through $crypt->setKey('...');
                $rsa->loadKey($this->getKey());
                // Encrypt the data and return it as a string
                $decrypt = $rsa->decrypt($data);
                return $decrypt;
                break;
            default:
                die("Cryptography for '$cryptType' not implemented yet!");
        }
    }

    public function getKey()
    {
        return $this->key;
    }

    public function setKey($key)
    {
        $this->key = $key;
    }

    public function getIv()
    {
        return $this->iv;
    }

    public function setIv($iv)
    {
        $this->iv = $iv;
    }

    public function getHash()
    {
        return $this->hash;
    }

    public function setHash($hash)
    {
        $this->hash = $hash;
    }

    public function resetAll()
    {
        $this->key = '';
        $this->iv = '';
        $this->hash = '';
    }
}

/** End of File: Crypt.php **/