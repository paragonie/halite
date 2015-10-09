<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Key;
use \ParagonIE\Halite\KeyPair;
use \ParagonIE\Halite\Symmetric\Crypto as Symmetric;

class Crypto implements Contract\AsymmetricKeyCryptoInterface
{
    /**
     * Encrypt a string using asymmetric cryptography
     * Wraps Symmetric::encrypt()
     * 
     * @param string $source Plaintext
     * @param string $ourPrivateKey Our private key
     * @param string $theirPublicKey Their public key
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function encrypt(
        $source, 
        Contract\CryptoKeyInterface $ourPrivateKey, 
        Contract\CryptoKeyInterface $theirPublicKey,
        $raw = false
    ) {
        list ($secret, $public) = self::judgeKeys($ourPrivateKey, $theirPublicKey);
        $ecdh = new Key(
            self::getSharedSecret($secret, $public),
            false, 
            false
        );
        
        $ciphertext = Symmetric::encrypt($source, $ecdh, $raw);
        unset($ecdh);
        return $ciphertext;
    }
    
    /**
     * Decrypt a string using asymmetric cryptography
     * Wraps Symmetric::decrypt()
     * 
     * @param string $source Ciphertext
     * @param string $ourPrivateKey Our private key
     * @param string $theirPublicKey Their public key
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function decrypt(
        $source,
        Contract\CryptoKeyInterface $ourPrivateKey,
        Contract\CryptoKeyInterface $theirPublicKey,
        $raw = false
    ) {
        list ($secret, $public) = self::judgeKeys($ourPrivateKey, $theirPublicKey);
        $ecdh = new Key(
            self::getSharedSecret($secret, $public),
            false, 
            false
        );
        
        $ciphertext = Symmetric::decrypt($source, $ecdh, $raw);
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
                $keys = Key::generate($type);
                return new KeyPair(...$keys);
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
     * @param Contract\CryptoKeyInterface $privatekey
     * @param Contract\CryptoKeyInterface $publickey
     * @param bool $get_as_object Get as a Key object?
     * 
     * @return string
     */
    public static function getSharedSecret(
        Contract\CryptoKeyInterface $privatekey,
        Contract\CryptoKeyInterface $publickey,
        $get_as_object = false
    ) {
        list ($secret, $public) = self::judgeKeys($privatekey, $publickey);
        
        if ($get_as_object) {
            return new Key(
                \Sodium\crypto_scalarmult(
                    $secret->get(),
                    $public->get()
                )
            );
        }
        return \Sodium\crypto_scalarmult(
            $secret->get(),
            $public->get()
        );
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string $source Message to encrypt
     * @param string $publicKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     */
    public static function seal(
        $source,
        Contract\CryptoKeyInterface $publicKey,
        $raw = false
    ) {
        if ($publicKey->isPublicKey()) {
            if (function_exists('\\Sodium\\crypto_box_seal')) {
                $sealed = \Sodium\crypto_box_seal($source, $publicKey->get());
            } else {
                /**
                 * Polyfill for libsodium < 1.0.3
                 */
                
                // Generate an ephemeral keypair
                $eph_kp = \Sodium\crypto_box_keypair();
                $eph_secret = \Sodium\crypto_box_secretkey($eph_kp);
                $eph_public = \Sodium\crypto_box_publickey($eph_kp);
                $seal_pubkey = $publicKey->get();
                $box_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
                    $eph_secret,
                    $seal_pubkey
                );
                
                // Calculate the nonce
                $nonce = \Sodium\crypto_generichash(
                    $eph_public . $seal_pubkey,
                    null,
                    \Sodium\CRYPTO_BOX_NONCEBYTES
                );
                
                // Seal the message
                $sealed = $eph_public . \Sodium\crypto_box(
                    $source,
                    $nonce,
                    $box_kp
                );
                
                // Don't forget to wipe
                \Sodium\memzero($seal_pubkey);
                \Sodium\memzero($eph_kp);
                \Sodium\memzero($eph_secret);
                \Sodium\memzero($eph_public);
                \Sodium\memzero($nonce);
                \Sodium\memzero($box_kp);
            }
            if ($raw) {
                return $sealed;
            }
            return \Sodium\bin2hex($sealed);
        }
        throw new CryptoException\InvalidKey(
            'Expected a public key'
        );
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string $message Message to sign
     * @param Contract\CryptoKeyInterface $privatekey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string Signature (detached)
     */
    public static function sign(
        $message,
        Contract\CryptoKeyInterface $privatekey,
        $raw = false
    ) {
        if (!$privatekey->isSigningKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a signing key'
            );
        }
        if (!$privatekey->isSecretKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a secret key'
            );
        }
        
        $signed = \Sodium\crypto_sign_detached(
            $message,
            $privatekey->get()
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
     * @param Contract\CryptoKeyInterface $privateKey
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     */
    public static function unseal(
        $source,
        Contract\CryptoKeyInterface $privateKey,
        $raw = false
    ) {
        if (!$raw) {
            $source = \Sodium\hex2bin($source);
        }
        if ($privateKey->isSecretKey()) {
            if (function_exists('\\Sodium\\crypto_box_seal_open')) {
                
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
                \Sodium\memzero($secret_key);
                \Sodium\memzero($public_key);
                \Sodium\memzero($kp);
            } else {
                /**
                 * Polyfill for libsodium < 1.0.3
                 */
                
                // Let's generate the box keypair
                $my_secret = $privateKey->get();
                $my_public = \Sodium\crypto_box_publickey_from_secretkey($my_secret);
                $eph_public = mb_substr(
                    $source,
                    0,
                    \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                    '8bit'
                );
                if (\mb_strlen($eph_public, '8bit') !== \Sodium\CRYPTO_BOX_PUBLICKEYBYTES) {
                    try { } catch (Exception $ex) { var_dump($ex->getTrace()); }
                    \var_dump([
                        'source' => \mb_strlen($source, '8bit'),
                        'src' => \Sodium\bin2hex($source),
                        'expect' => \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                        'gotten' => \mb_strlen($eph_public, '8bit')
                    ]);
                    throw new CryptoException\CannotPerformOperation('What even is a string length');
                }
                
                $box_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
                    $my_secret,
                    $eph_public
                );
                
                // Calculate the nonce as libsodium does
                $nonce = \Sodium\crypto_generichash(
                    $eph_public . $my_public,
                    null,
                    \Sodium\CRYPTO_BOX_NONCEBYTES
                );
                
                // $boxed is the ciphertext from crypto_box_seal
                $boxed = mb_substr(
                    $source,
                    \Sodium\CRYPTO_BOX_PUBLICKEYBYTES,
                    null,
                    '8bit'
                );
                
                $message = \Sodium\crypto_box_open(
                    $boxed,
                    $nonce,
                    $box_kp
                );
                \Sodium\memzero($my_secret);
                \Sodium\memzero($my_public);
                \Sodium\memzero($box_kp);
                \Sodium\memzero($nonce);
                \Sodium\memzero($eph_public);
            }
            if ($message === false) {
                throw new CryptoException\InvalidKey(
                    'Incorrect secret key'
                );
            }
            
            // We have our encrypted message here
            return $message;
        }
        throw new CryptoException\InvalidKey(
            'Expected a secret key'
        );
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
        Contract\CryptoKeyInterface $publickey,
        $signature,
        $raw = false
    ) {
        if (!$publickey->isSigningKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a signing key'
            );
        }
        if (!$publickey->isPublicKey()) {
            throw new CryptoException\InvalidKey(
                'Expected a public key'
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
    
    /**
     * We are expecting one secret key and one public key
     * 
     * @param type $privatekey
     * @param type $publickey
     * @return [Key, Key] secret, public
     * @throws CryptoException\InvalidKey
     */
    protected static function judgeKeys(Contract\CryptoKeyInterface $privatekey, Contract\CryptoKeyInterface $publickey)
    {
        if ($privatekey->isPublicKey()) {
            if ($publickey->isPublicKey()) {
                throw new CryptoException\InvalidKey(
                    'Both keys cannot be public keys'
                );
            }
            return [
                $publickey,
                $privatekey
            ];
        } elseif ($publickey->isPublicKey()) {
            return [
                $privatekey,
                $publickey
            ];
        } else {
            throw new CryptoException\InvalidKey(
                'Both keys cannot be secret keys'
            );
        }
    }
}