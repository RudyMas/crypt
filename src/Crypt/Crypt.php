<?php

namespace RudyMas\Crypt;

use phpseclib\Crypt\AES;
use phpseclib\Crypt\DES;
use phpseclib\Crypt\Random;
use phpseclib\Crypt\RSA;
use RudyMas\Manipulator\Text;

/**
 * Class Crypt (PHP version 7.1)
 * A wrapper for phpseclib (Cryptography)
 *
 * This class is used in combination with following class:
 *    - phpseclib (composer install phpseclib/phpseclib)
 *    - manipulator/text (composer install rudymas/manipulator)
 *
 * @author      Rudy Mas <rudy.mas@rmsoft.be>
 * @copyright   2016-2018, rmsoft.be. (http://www.rmsoft.be/)
 * @license     https://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3 (GPL-3.0)
 * @version     0.7.0
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
     * @param string $cryptType
     * @param string $data
     * @return string
     */
    public function encrypt(string $cryptType, string $data): string
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
     * @param string $cryptType
     * @param string $data
     * @return string
     */
    public function decrypt(string $cryptType, string $data): string
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

    /**
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @param string $key
     */
    public function setKey(string $key)
    {
        $this->key = $key;
    }

    /**
     * @return string
     */
    public function getIv(): string
    {
        return $this->iv;
    }

    /**
     * @param string $iv
     */
    public function setIv(string $iv)
    {
        $this->iv = $iv;
    }

    /**
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * @param string $hash
     */
    public function setHash(string $hash)
    {
        $this->hash = $hash;
    }

    /**
     * Reset key, iv & hash
     */
    public function resetAll(): void
    {
        $this->key = '';
        $this->iv = '';
        $this->hash = '';
    }
}

/** End of File: Crypt.php **/