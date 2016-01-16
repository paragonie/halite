<?php
declare(strict_types=1);
namespace Sodium;

/**
 * To silence the phpstorm "unknown namespace" errors.
 *
 * This does nothing if the libsodium extension is loaded, so it's harmless.
 */
if (!\extension_loaded('libsodium')) {
    function crypto_aead_aes256gcm_is_available(): bool
    {
        return false;
    }

    function crypto_aead_aes256gcm_decrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        return '';
    }

    function crypto_aead_aes256gcm_encrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        return '';
    }

    function crypto_aead_chacha20poly1305_decrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        return '';
    }

    function crypto_aead_chacha20poly1305_encrypt(
        string $msg,
        string $nonce,
        string $key,
        string $ad = ''
    ): string {
        return '';
    }

    function crypto_auth(
        string $msg,
        string $key
    ): string {
        return '';
    }

    function crypto_auth_verify(
        string $mac,
        string $msg,
        string $key
    ): bool {
        return false;
    }

    function crypto_box(
        string $msg,
        string $nonce,
        string $keypair
    ): string {
        return '';
    }

    function crypto_box_keypair(): string {
        return '';
    }

    function crypto_box_seed_keypair(
        string $seed
    ): string {
        return '';
    }

    function crypto_box_keypair_from_secretkey_and_publickey(
        string $secretkey,
        string $publickey
    ): string {
        return '';
    }

    function crypto_box_open(
        string $msg,
        string $nonce,
        string $keypair
    ): string {
        return '';
    }

    function crypto_box_publickey(
        string $keypair
    ): string {
        return '';
    }

    function crypto_box_publickey_from_secretkey(
        string $secretkey
    ): string {
        return '';
    }

    function crypto_box_seal(
        string $message,
        string $publickey
    ): string {
        return '';
    }
    function crypto_box_seal_open(
        string $encrypted,
        string $keypair
    ): string {
        return '';
    }
    function crypto_box_secretkey(): string
    {
        return '';
    }

    function crypto_kx(
        string $client_secret,
        string $server_public,
        string $client_public,
        string $server_public_again
    ): string {
        return '';
    }
    function crypto_generichash(
        string $input,
        string $key = '',
        int $length = 32
    ): string{
        return '';
    }

    function crypto_generichash_init(
        string $key = '',
        int $length = 32
    ): string {
        return '';
    }

    function crypto_generichash_update(
        string $hashState,
        string $append
    ): string {
        return '';
    }

    function crypto_generichash_final(
        string $state,
        int $length = 32
    ): string {
        return '';
    }

    function crypto_pwhash(
        int $out_len,
        string $passwd,
        string $salt,
        int $opslimit,
        int $memlimit
    ): string {
        return '';
    }

    function crypto_pwhash_str(
        string $passwd,
        int $opslimit,
        int $memlimit
    ): string {
        return '';
    }

    function crypto_pwhash_str_verify(
        string $hash,
        string $passwd
    ): bool {
        return false;
    }

    function crypto_pwhash_scryptsalsa208sha256(
        int $out_len,
        string $passwd,
        string $salt,
        int $opslimit,
        int $memlimit
    ): string {
        return '';
    }

    function crypto_pwhash_scryptsalsa208sha256_str(
        string $passwd,
        int $opslimit,
        int $memlimit
    ): string {
        return '';
    }

    function crypto_pwhash_scryptsalsa208sha256_str_verify(
        string $hash,
        string $passwd
    ): bool {
        return false;
    }

    function crypto_scalarmult(
        string $ecdhA,
        string $ecdhB
    ): string {
        return '';
    }

    function crypto_secretbox(
        string $plaintext,
        string $nonce,
        string $key
    ): string {
        return '';
    }

    function crypto_secretbox_open(
        string $ciphertext,
        string $nonce,
        string $key
    ): string {
        return '';
    }

    function crypto_shorthash(
        string $message,
        string $key
    ): string {
        return '';
    }

    function crypto_sign(
        string $message,
        string $secretkey
    ): string {
        return '';
    }

    function crypto_sign_detached(
        string $message,
        string $secretkey
    ): string {
        return '';
    }

    function crypto_sign_ed25519_pk_to_curve25519(
        string $sign_pk
    ): string {
        return '';
    }

    function crypto_sign_ed25519_sk_to_curve25519(
        string $sign_sk
    ): string {
        return '';
    }

    function crypto_sign_keypair(): string
    {
        return '';
    }

    function crypto_sign_keypair_from_secretkey_and_publickey(
        string $secretkey,
        string $publickey
    ): string {
        return '';
    }

    function crypto_sign_open(
        string $message,
        string $publickey
    ): string {
        return '';
    }

    function crypto_sign_publickey(): string
    {
        return '';
    }

    function crypto_sign_secretkey(): string
    {
        return '';
    }

    function crypto_sign_publickey_from_secretkey(
        string $secretkey
    ): string {
        return '';
    }

    function crypto_sign_seed_keypair(
        string $seed
    ): string {
        return '';
    }

    function crypto_sign_verify_detached(
        string $signature,
        string $msg,
        string $Publickey
    ): bool {
        return false;
    }

    function crypto_stream(
        string $plaintext,
        string $nonce,
        string $key
    ): string {
        return '';
    }

    function crypto_stream_xor(
        string $plaintext,
        string $nonce,
        string $key
    ): string {
        return '';
    }

    function randombytes_buf(
        int $length
    ): string {
        return '';
    }

    function randombytes_random16(): string {
        return '';
    }

    function randombytes_uniform(
        int $upperBoundNonInclusive
    ): int {
        return 0;
    }

    function bin2hex(
        string $binary
    ): string {
        return '';
    }

    function compare(
        string $left,
        string $right
    ): int {
        return 0;
    }

    function hex2bin(
        string $hex
    ): string {
        return '';
    }
    function increment(
        string $nonce
    ): string {
        return '';
    }

    function add(
        string $left,
        string $right
    ): string {
        return '';
    }

    function library_version_major(): int {
        return 0;
    }

    function library_version_minor(): int {
        return 0;
    }
    function memcmp(
        string $left,
        string $right
    ): int {
        return 0;
    }

    function memzero(
        string &$target
    ) {
        $target = '';
        return;
    }

    function version_string(): string {
        return 'NA';
    }

    function crypto_scalarmult_base(
        string $sk
    ): string {
        return '';
    }
}