<?php
namespace ParagonIE\Halite\Asymmetric;

use \ParagonIE\Halite\Alerts as CryptoException;
use \ParagonIE\Halite\Util as CryptoUtil;
use \ParagonIE\Halite\Contract;
use \ParagonIE\Halite\Symmetric\Crypto as SymmetricCrypto;
use \ParagonIE\Halite\Symmetric\EncryptionKey;

abstract class Crypto implements Contract\AsymmetricKeyCryptoInterface
{
    /**
     * Encrypt a string using asymmetric cryptography
     * Wraps SymmetricCrypto::encrypt()
     * 
     * @param string $source Plaintext
     * @param EncryptionSecretKey $ourPrivateKey Our private key
     * @param EncryptionPublicKey $theirPublicKey  Their public key
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     * 
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     */
    public static function encrypt(
        $source,
        Contract\KeyInterface $ourPrivateKey,
        Contract\KeyInterface $theirPublicKey,
        $raw = false
    ) {
        if (!\is_string($source)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the plaintext as a string'
            );
        }
        if (!$ourPrivateKey instanceof EncryptionSecretKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionSecretKey'
            );
        }
        if (!$theirPublicKey instanceof EncryptionPublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 3: Expected an instance of EncryptionPublicKey'
            );
        }
        $ecdh = new EncryptionKey(
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
     * @param EncryptionSecretKey $ourPrivateKey Our private key
     * @param EncryptionPublicKey $theirPublicKey Their public key
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     * 
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     */
    public static function decrypt(
        $source,
        Contract\KeyInterface $ourPrivateKey,
        Contract\KeyInterface $theirPublicKey,
        $raw = false
    ) {
        if (!\is_string($source)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the ciphertext as a string'
            );
        }
        if (!$ourPrivateKey instanceof EncryptionSecretKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionSecretKey'
            );
        }
        if (!$theirPublicKey instanceof EncryptionPublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 3: Expected an instance of EncryptionPublicKey'
            );
        }
        $ecdh = new EncryptionKey(
            self::getSharedSecret($ourPrivateKey, $theirPublicKey)
        );
        /** @var string $ciphertext */
        $ciphertext = SymmetricCrypto::decrypt($source, $ecdh, $raw);
        unset($ecdh);
        return $ciphertext;
    }
    
    /**
     * Diffie-Hellman, ECDHE, etc.
     * 
     * Get a shared secret from a private key you possess and a public key for
     * the intended message recipient
     * 
     * @param EncryptionSecretKey $privateKey
     * @param EncryptionPublicKey $publicKey
     * @param bool $get_as_object Get as a Key object?
     * 
     * @return string
     * 
     * @throws CryptoException\InvalidKey
     */
    public static function getSharedSecret(
        Contract\KeyInterface $privateKey,
        Contract\KeyInterface $publicKey,
        $get_as_object = false
    ) {
        if (!$privateKey instanceof EncryptionSecretKey) {
            throw new CryptoException\InvalidKey(
                'Argument 1: Expected an instance of EncryptionSecretKey'
            );
        }
        if (!$publicKey instanceof EncryptionPublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionPublicKey'
            );
        }
        if ($get_as_object) {
            return new EncryptionKey(
                \Sodium\crypto_scalarmult(
                    $privateKey->get(),
                    $publicKey->get()
                )
            );
        }
        return (string) \Sodium\crypto_scalarmult(
            $privateKey->get(),
            $publicKey->get()
        );
    }
    
    /**
     * Encrypt a message with a target users' public key
     * 
     * @param string $source Message to encrypt
     * @param EncryptionPublicKey $publicKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string
     *
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     * @throws CryptoException\CannotPerformOperation
     */
    public static function seal(
        $source,
        Contract\KeyInterface $publicKey,
        $raw = false
    ) {
        if (!\is_string($source)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the plaintext as a string'
            );
        }
        if (!$publicKey instanceof EncryptionPublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionPublicKey'
            );
        }
        if (!\is_callable('\\Sodium\\crypto_box_seal')) {
            throw new CryptoException\CannotPerformOperation(
                'crypto_box_seal is not available'
            );
        }

        /** @var string $sealed */
        $sealed = \Sodium\crypto_box_seal($source, $publicKey->get());
        if ($raw) {
            return (string) $sealed;
        }
        return (string) \Sodium\bin2hex($sealed);
    }
    
    /**
     * Sign a message with our private key
     * 
     * @param string $message Message to sign
     * @param SignatureSecretKey $privateKey
     * @param boolean $raw Don't hex encode the output?
     * 
     * @return string Signature (detached)
     *
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     */
    public static function sign(
        $message,
        Contract\KeyInterface $privateKey,
        $raw = false
    ) {
        if (!\is_string($message)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the message as a string'
            );
        }
        if (!$privateKey instanceof SignatureSecretKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of SignatureSecretKey'
            );
        }
        /** @var string $signed */
        $signed = \Sodium\crypto_sign_detached(
            $message,
            $privateKey->get()
        );
        if ($raw) {
            return (string) $signed;
        }
        return (string) \Sodium\bin2hex($signed);
    }
    
    /**
     * Decrypt a sealed message with our private key
     * 
     * @param string $source Encrypted message (string or resource for a file)
     * @param EncryptionSecretKey $privateKey
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return string
     * 
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     * @throws CryptoException\CannotPerformOperation
     */
    public static function unseal(
        $source,
        Contract\KeyInterface $privateKey,
        $raw = false
    ) {
        if (!\is_string($source)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the ciphertext as a string'
            );
        }
        if (!$privateKey instanceof EncryptionSecretKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of EncryptionSecretKey'
            );
        }
        if (!$raw) {
            /** @var string $source */
            $source = \Sodium\hex2bin($source);
        }
        if (!\is_callable('\\Sodium\\crypto_box_seal_open')) {
            throw new CryptoException\CannotPerformOperation(
                'crypto_box_seal_open is not available, please update/reinstall libsodium'
            );
        }

        // Get a box keypair (needed by crypto_box_seal_open)

        /** @var string $secret_key */
        $secret_key = $privateKey->get();
        /** @var string $public_key */
        $public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
        /** @var string $kp */
        $kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $secret_key,
            $public_key
        );
        
        // Wipe these immediately:
        \Sodium\memzero($secret_key);
        \Sodium\memzero($public_key);
        
        // Now let's open that sealed box
        /** @var string $message */
        $message = \Sodium\crypto_box_seal_open($source, $kp);

        // Always memzero after retrieving a value
        \Sodium\memzero($kp);
        if ($message === false) {
            throw new CryptoException\InvalidKey(
                'Incorrect secret key for this sealed message'
            );
        }

        // We have our encrypted message here
        return $message;
    }
    
    /**
     * Verify a signed message with the correct public key
     * 
     * @param string $message Message to verify
     * @param SignaturePublicKey $publicKey
     * @param string $signature
     * @param boolean $raw Don't hex decode the input?
     * 
     * @return bool
     *
     * @throws CryptoException\InvalidKey
     * @throws CryptoException\InvalidType
     * @throws CryptoException\InvalidSignature
     * @throws CryptoException\CannotPerformOperation
     */
    public static function verify(
        $message,
        Contract\KeyInterface $publicKey,
        $signature,
        $raw = false
    ) {
        if (!\is_string($message)) {
            throw new CryptoException\InvalidType(
                'Argument 1: Expected the message as a string'
            );
        }
        if (!$publicKey instanceof SignaturePublicKey) {
            throw new CryptoException\InvalidKey(
                'Argument 2: Expected an instance of SignaturePublicKey'
            );
        }
        if (!\is_string($signature)) {
            throw new CryptoException\InvalidType(
                'Argument 3: Expected the signature as a string'
            );
        }
        if (!$raw) {
            /** @var string $signature */
            $signature = \Sodium\hex2bin($signature);
        }
        if (CryptoUtil::safeStrlen($signature) !== \Sodium\CRYPTO_SIGN_BYTES) {
            throw new CryptoException\InvalidSignature(
                'Signature is not the correct length; is it encoded?'
            );
        }
        
        return (bool) \Sodium\crypto_sign_verify_detached(
            $signature,
            $message,
            $publicKey->get()
        );
    }
}
