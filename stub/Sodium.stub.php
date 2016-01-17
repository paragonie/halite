<?php
declare(strict_types=1);
namespace Sodium;

/**
 * To silence the phpstorm "unknown namespace" errors.
 *
 * This does nothing if the libsodium extension is loaded, so it's harmless.
 * 
 * This file alone is released under CC0 and WTFPL dual licensing.
 */
if (!\extension_loaded('libsodium')) {
    /**
     * Can you access AES-256-GCM? This is only available if you have supported
     * hardware.
     * 
     * @return bool
     */
    function crypto_aead_aes256gcm_is_available()
    {
        return false;
    }

    /**
     * Authenticated Encryption with Associated Data (decrypt)
     * AES-256-GCM
     * 
     * @param string $msg encrypted message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     */
    function crypto_aead_aes256gcm_decrypt(
        $msg,
        $nonce,
        $key,
        $ad = ''
    ) {
        return '';
    }

    /**
     * Authenticated Encryption with Associated Data (encrypt)
     * AES-256-GCM
     * 
     * @param string $msg plaintext message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     */
    function crypto_aead_aes256gcm_encrypt(
        $msg,
        $nonce,
        $key,
        $ad = ''
    ) {
        return '';
    }

    /**
     * Authenticated Encryption with Associated Data (decrypt)
     * ChaCha20 + Poly1305
     * 
     * @param string $msg encrypted message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     */
    function crypto_aead_chacha20poly1305_decrypt(
        $msg,
        $nonce,
        $key,
        $ad = ''
    ) {
        return '';
    }

    /**
     * Authenticated Encryption with Associated Data (encrypt)
     * ChaCha20 + Poly1305
     * 
     * @param string $msg plaintext message
     * @param string $nonce
     * @param string $key
     * @param string $ad additional data (optional)
     * @return string
     */
    function crypto_aead_chacha20poly1305_encrypt(
        $msg,
        $nonce,
        $key,
        $ad = ''
    ) {
        return '';
    }

    /**
     * Secret-key message authentication
     * HMAC SHA-512/256
     * 
     * @param string $msg
     * @param string $key
     * @return string
     */
    function crypto_auth(
        $msg,
        $key
    ) {
        return '';
    }

    /**
     * Secret-key message verification
     * HMAC SHA-512/256
     * 
     * @param string $mac
     * @param string $msg
     * @param string $key
     * @return bool
     */
    function crypto_auth_verify(
        $mac,
        $msg,
        $key
    ) {
        return false;
    }

    /**
     * Public-key authenticated encryption (encrypt)
     * X25519 + Xsalsa20 + Poly1305
     * 
     * @param string $msg
     * @param string $nonce
     * @param string $keypair
     * @return string
     */
    function crypto_box(
        $msg,
        $nonce,
        $keypair
    ) {
        return '';
    }

    /**
     * Generate an X25519 keypair for use with the crypto_box API
     * 
     * @return string
     */
    function crypto_box_keypair() {
        return '';
    }

    /**
     * Derive an X25519 keypair for use with the crypto_box API from a seed
     * 
     * @param string $seed
     * @return string
     */
    function crypto_box_seed_keypair(
        $seed
    ) {
        return '';
    }

    /**
     * Create an X25519 keypair from an X25519 secret key and X25519 public key
     * 
     * @param string $secretkey
     * @param string $publickey
     * @return string
     */
    function crypto_box_keypair_from_secretkey_and_publickey(
        $secretkey,
        $publickey
    ) {
        return '';
    }

    /**
     * Public-key authenticated encryption (decrypt)
     * X25519 + Xsalsa20 + Poly1305
     * 
     * @param string $msg
     * @param string $nonce
     * @param string $keypair
     * @return string
     */
    function crypto_box_open(
        $msg,
        $nonce,
        $keypair
    ) {
        return '';
    }

    /**
     * Get an X25519 public key from an X25519 keypair
     * 
     * @param string $keypair
     * @return string
     */
    function crypto_box_publickey(
        $keypair
    ) {
        return '';
    }

    /**
     * Derive an X25519 public key from an X25519 secret key
     * 
     * @param string $secretkey
     * @return string
     */
    function crypto_box_publickey_from_secretkey(
        $secretkey
    ) {
        return '';
    }

    /**
     * Anonymous public-key encryption (encrypt)
     * X25519 + Xsalsa20 + Poly1305 + BLAKE2b
     * 
     * @param string $message
     * @param string $publickey
     */
    function crypto_box_seal(
        $message,
        $publickey
    ) {
        return '';
    }
    
    /**
     * Anonymous public-key encryption (decrypt)
     * X25519 + Xsalsa20 + Poly1305 + BLAKE2b
     * 
     * @param string $encrypted
     * @param string $keypair
     */
    function crypto_box_seal_open(
        $encrypted,
        $keypair
    ) {
        return '';
    }
    
    /**
     * Extract the X25519 secret key from an X25519 keypair
     * 
     * @param string $keypair
     * @return string
     */
    function crypto_box_secretkey(string $keypair)
    {
        return '';
    }

    /**
     * Elliptic Curve Diffie Hellman Key Exchange
     * X25519
     * 
     * @param string $secretkey
     * @param string $publickey
     * @param string $client_publickey
     * @param string $server_publickey
     * @return string
     */
    function crypto_kx(
        $secretkey,
        $publickey,
        $client_publickey,
        $server_publickey
    ) {
        return '';
    }
    
    /**
     * Fast and secure cryptographic hash
     * 
     * @param string $input
     * @param string $key
     * @param int $length
     * @return string
     */
    function crypto_generichash(
        $input,
        $key = '',
        $length = 32
    ){
        return '';
    }

    /**
     * Create a new hash state (e.g. to use for streams)
     * BLAKE2b
     * 
     * @param string $key
     * @param int $length
     * @return string
     */
    function crypto_generichash_init(
        $key = '',
        $length = 32
    ) {
        return '';
    }

    /**
     * Update the hash state with some data
     * BLAKE2b
     * 
     * @param &string $hashState
     * @param string $append
     * @return bool
     */
    function crypto_generichash_update(
        string &$hashState,
        $append
    ) {
        return '';
    }

    /**
     * Get the final hash
     * BLAKE2b
     * 
     * @param string $hashState
     * @param int $length
     * @return string
     */
    function crypto_generichash_final(
        $state,
        $length = 32
    ) {
        return '';
    }

    /**
     * Secure password-based key derivation function
     * Argon2i
     * 
     * @param int $out_len
     * @param string $passwd
     * @param string $salt
     * @param int $opslimit
     * @param int $memlimit
     * @return $string
     */
    function crypto_pwhash(
        $out_len,
        $passwd,
        $salt,
        $opslimit,
        $memlimit
    ) {
        return '';
    }

    /**
     * Get a formatted password hash (for storage)
     * Argon2i
     * 
     * @param string $passwd
     * @param int $opslimit
     * @param int $memlimit
     * @return $string
     */
    function crypto_pwhash_str(
        $passwd,
        int $opslimit,
        int $memlimit
    ) {
        return '';
    }

    /**
     * Verify a password against a hash
     * Argon2i
     * 
     * @param string $hash
     * @param string $passwd
     * @return bool
     */
    function crypto_pwhash_str_verify(
        $hash,
        $passwd
    ) {
        return false;
    }

    /**
     * Secure password-based key derivation function
     * Scrypt
     * 
     * @param int $out_len
     * @param string $passwd
     * @param string $salt
     * @param int $opslimit
     * @param int $memlimit
     * @return $string
     */
    function crypto_pwhash_scryptsalsa208sha256(
        int $out_len,
        $passwd,
        $salt,
        int $opslimit,
        int $memlimit
    ) {
        return '';
    }

    /**
     * Get a formatted password hash (for storage)
     * Scrypt
     * 
     * @param string $passwd
     * @param int $opslimit
     * @param int $memlimit
     * @return $string
     */
    function crypto_pwhash_scryptsalsa208sha256_str(
        $passwd,
        $opslimit,
        $memlimit
    ) {
        return '';
    }

    /**
     * Verify a password against a hash
     * Scrypt
     * 
     * @param string $hash
     * @param string $passwd
     * @return bool
     */
    function crypto_pwhash_scryptsalsa208sha256_str_verify(
        $hash,
        $passwd
    ) {
        return false;
    }

    /**
     * Elliptic Curve Diffie Hellman over Curve25519
     * X25519
     * 
     * @param string $ecdhA
     * @param string $ecdhB
     * @return string
     */
    function crypto_scalarmult(
        $ecdhA,
        $ecdhB
    ) {
        return '';
    }

    /**
     * Authenticated secret-key encryption (encrypt)
     * Xsals20 + Poly1305
     * 
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_secretbox(
        $plaintext,
        $nonce,
        $key
    ) {
        return '';
    }

    /**
     * Authenticated secret-key encryption (decrypt)
     * Xsals20 + Poly1305
     * 
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_secretbox_open(
        $ciphertext,
        $nonce,
        $key
    ) {
        return '';
    }

    /**
     * A short keyed hash suitable for data structures
     * SipHash-2-4
     * 
     * @param string $message
     * @param string $key
     * @return string
     */
    function crypto_shorthash(
        $message,
        $key
    ) {
        return '';
    }

    /**
     * Digital Signature
     * Ed25519
     * 
     * @param string $message
     * @param string $secretkey
     * @return string
     */
    function crypto_sign(
        $message,
        $secretkey
    ) {
        return '';
    }

    /**
     * Digital Signature (detached)
     * Ed25519
     * 
     * @param string $message
     * @param string $secretkey
     * @return string
     */
    function crypto_sign_detached(
        $message,
        $secretkey
    ) {
        return '';
    }

    /**
     * Convert an Ed25519 public key to an X25519 public key
     * 
     * @param string $sign_pk
     * @return string
     */
    function crypto_sign_ed25519_pk_to_curve25519(
        $sign_pk
    ) {
        return '';
    }

    /**
     * Convert an Ed25519 secret key to an X25519 secret key
     * 
     * @param string $sign_sk
     * @return string
     */
    function crypto_sign_ed25519_sk_to_curve25519(
        $sign_sk
    ) {
        return '';
    }

    /**
     * Generate an Ed25519 keypair for use with the crypto_sign API
     * 
     * @return string
     */
    function crypto_sign_keypair()
    {
        return '';
    }


    /**
     * Create an Ed25519 keypair from an Ed25519 secret key + Ed25519 public key
     * 
     * @param string $secretkey
     * @param string $publickey
     * @return string
     */
    function crypto_sign_keypair_from_secretkey_and_publickey(
        $secretkey,
        $publickey
    ) {
        return '';
    }

    /**
     * Verify a signed message and return the plaintext
     * 
     * @param string $signed_message
     * @param string $publickey
     * @return string
     */
    function crypto_sign_open(
        $signed_message,
        $publickey
    ) {
        return '';
    }

    /**
     * Get the public key from an Ed25519 keypair
     * 
     * @param string $keypair
     */
    function crypto_sign_publickey(
        $keypair
    ) {
        return '';
    }

    /**
     * Get the secret key from an Ed25519 keypair
     * 
     * @param string $keypair
     */
    function crypto_sign_secretkey(
        $keypair
    ) {
        return '';
    }

    /**
     * Derive an Ed25519 public key from an Ed25519 secret key
     * 
     * @param string $secretkey
     * @return string
     */
    function crypto_sign_publickey_from_secretkey(
        $secretkey
    ) {
        return '';
    }

    /**
     * Derive an Ed25519 keypair for use with the crypto_sign API from a seed
     * 
     * @param string $seed
     * @return string
     */
    function crypto_sign_seed_keypair(
        $seed
    ) {
        return '';
    }

    /**
     * Verify a detached signature
     * 
     * @param string $signature
     * @param string $msg
     * @param string $publickey
     * @return bool
     */
    function crypto_sign_verify_detached(
        $signature,
        $msg,
        $publickey
    ) {
        return false;
    }

    /**
     * Create a keystream from a key and nonce
     * Xsalsa20
     * 
     * @param int $length
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_stream(
        int $length,
        $nonce,
        $key
    ) {
        return '';
    }

    /**
     * Encrypt a message using a stream cipher
     * Xsalsa20
     * 
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_stream_xor(
        $plaintext,
        $nonce,
        $key
    ) {
        return '';
    }

    /**
     * Generate a string of random bytes
     * /dev/urandom
     * 
     * @param int $length
     * @return string
     */
    function randombytes_buf(
        int $length
    ) {
        return '';
    }

    /**
     * Generate a 16-bit integer
     * /dev/urandom
     * 
     * @return int
     */
    function randombytes_random16() {
        return '';
    }

    /**
     * Generate an unbiased random integer between 0 and a specified value
     * /dev/urandom
     * 
     * @param int $upperBoundNonInclusive
     * @return int
     */
    function randombytes_uniform(
        int $upperBoundNonInclusive
    ) {
        return 0;
    }

    /**
     * Convert to hex without side-chanels
     * 
     * @param string $binary
     * @return string
     */
    function bin2hex(
        $binary
    ) {
        return '';
    }

    /**
     * Compare two strings in constant time
     * 
     * @param string $left
     * @param string $right
     * @return int
     */
    function compare(
        $left,
        $right
    ) {
        return 0;
    }

    /**
     * Convert from hex without side-chanels
     * 
     * @param string $binary
     * @return string
     */
    function hex2bin(
        $hex
    ) {
        return '';
    }
    
    /**
     * Increment a string in little-endian
     * 
     * @param &string $nonce
     */
    function increment(
        &$nonce
    ) {
        return '';
    }

    /**
     * Add the right operand to the left
     * 
     * @param &string $left
     * @param string $right
     */
    function add(
        &$left,
        $right
    ) {
        return '';
    }

    /**
     * Get the true major version of libsodium
     * @return int
     */
    function library_version_major() {
        return 0;
    }

    /**
     * Get the true minor version of libsodium
     * @return int
     */
    function library_version_minor() {
        return 0;
    }
    
    /**
     * Compare two strings in constant time
     * 
     * @param string $left
     * @param string $right
     * @return int
     */
    function memcmp(
        $left,
        $right
    ) {
        return 0;
    }

    /**
     * Wipe a buffer
     * 
     * @param &string $nonce
     */
    function memzero(
        &$target
    ) {
        $target = '';
    }

    /**
     * Get the version string
     * 
     * @return string
     */
    function version_string() {
        return 'NA';
    }

    /**
     * Scalar multiplication of the base point and your key
     * 
     * @param string $sk
     * @return string
     */
    function crypto_scalarmult_base(
        $sk
    ) {
        return '';
    }
}