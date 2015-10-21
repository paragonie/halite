<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Asymmetric\PublicKey;
use \ParagonIE\Halite\Asymmetric\SecretKey;
use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use \ParagonIE\Halite\Symmetric\SecretKey as SymmetricKey;

class Crypto implements Contract\AsymmetricKeyCryptoInterface
{
    /**
     * Encrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::encrypt()
     * 
     * @param string $source Plaintext
     * @param SecretKey $ourPrivateKey Our private key
     * @param PublicKey $theirPublicKey  Their public key
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function encrypt(
        $source, 
        SecretKey $ourPrivateKey, 
        PublicKey $theirPublicKey,
        $raw = false
    ) {
        $ecdh = new SymmetricKey(
            self::getSharedSecret($ourPrivateKey, $theirPublicKey)
        );
        $ciphertext = SymmetricCrypto::encrypt($source, $ecdh, $raw);
        unset($ecdh);
        return $ciphertext;
    }
    
    /**
     * Decrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::decrypt()
     * 
     * @param string $source Ciphertext
     * @param SecretKey $ourPrivateKey Our private key
     * @param PublicKey $theirPublicKey Their public key
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function decrypt(
        $source,
        SecretKey $ourPrivateKey,
        PublicKey $theirPublicKey,
        $raw = false
    ) {
        $ecdh = new SymmetricKey(
            self::getSharedSecret($ourPrivateKey, $theirPublicKey)
        );
        $ciphertext = SymmetricCrypto::decrypt($source, $ecdh, $raw);
        unset($ecdh);
        return $ciphertext;
    }
    /**
     * Generate a keypair
     * 
     * @param array $type
     */
    public static function generateKeys($type = Key::CRYPTO_BOX)
    {
        if ($type & Key::ASYMMETRIC === 0) {
            throw new CryptoException\InvalidFlags;
        }
        
        switch ($type) {
            case Key::ENCRYPTION:
            case Key::SIGNATURE:
            case Key::CRYPTO_SIGN:
            case Key::CRYPTO_BOX:
                return KeyPair::generate($type);
            default:
                throw new CryptoException\InvalidKey;
        }
    }
    
    /**
     * Diffie-Hellman, ECDHE, etc.
     * 
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     * 
     * @param SecretKey $privateKey
     * @param PublicKey $publicKey
     * @param bool $get_as_object Get as a Key object?
     * 
     * @return string
     */
    public static function getSharedSecret(
        SecretKey $privateKey,
        PublicKey $publicKey,
        $get_as_object = false
    ) {
        if ($get_as_object) {
            return new SymmetricKey(
                \Sodium\crypto_scalarmult(
                    $privateKey->get(),
                    $publicKey->get()
                )
            );
        }
        return \Sodium\crypto_scalarmult(
            $privateKey->get(),
            $publicKey->get()
        );
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string $source Message to encrypt
     * @param PublicKey $publicKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function seal(
        $source,
        PublicKey $publicKey,
        $raw = false
    ) {
        if (!function_exists('\\Sodium\\crypto_box_seal')) {
            throw new CryptoException\CannotPerformOperation(
                'crypto_box_seal is not available'
            );
        }
        
        $pubkey = $publicKey->get();
        $sealed = \Sodium\crypto_box_seal($source, $pubkey);
        if ($raw) {
            return $sealed;
        }
        return \Sodium\bin2hex($sealed);
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string $message Message to sign
     * @param SecretKey $privateKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string Signature (detached)
     */
    public static function sign(
        $message,
        SecretKey $privateKey,
        $raw = false
    ) {
        if (!$privateKey->isSigningKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a signing key'
            );
        }
        
        $signed = \Sodium\crypto_sign_detached(
            $message,
            $privateKey->get()
        );
        if ($raw) {
            return $signed;
        }
        return \Sodium\bin2hex($signed);
    }
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string $source Encrypted message (string or resource for a file)
     * @param SecretKey $privateKey
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function unseal(
        $source,
        SecretKey $privateKey,
        $raw = false
    ) {
        if (!$raw) {
            $source = \Sodium\hex2bin($source);
        }
        if (!function_exists('\\Sodium\\crypto_box_seal_open')) {
            throw new CryptoException\CannotPerformOperation(
                'crypto_box_seal_open is not available'
            );
        }

        // Get a box keypair (needed by crypto_box_seal_open)
        $secret_key = $privateKey->get();
        
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        
        $kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        // Now let's open that sealed box
        $message = \Sodium\crypto_box_seal_open($source, $kp);

        // Always memzero after retrieving a value
        \Sodium\memzero($kp);
        if ($message === false) {
            throw new CryptoException\InvalidKey(
                'Incorrect secret key'
            );
        }

        // We have our encrypted message here
        return $message;
    }
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string $message Message to verify
     * @param Key $publickey
     * @param string $signature
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return boolean
     */
    public static function verify(
        $message,
        PublicKey $publickey,
        $signature,
        $raw = false
    ) {
        if (!$publickey->isSigningKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a signing key'
            );
        }
        if (!$raw) {
            $signature = \Sodium\hex2bin($signature);
        }
        
        return \Sodium\crypto_sign_verify_detached(
            $signature,
            $message,
            $publickey->get()
        );
    }
}