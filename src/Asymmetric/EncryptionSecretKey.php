<?php
namespace ParagonIE\Halite\Asymmetric;

final class EncryptionSecretKey extends SecretKey
{
    /**
     * @param string $keyMaterial - The actual key data
     * @param bool $signing - Is this a signing key?
     */
    public function __construct($keyMaterial = '', ...$args) 
    {
        parent::__construct($keyMaterial, false);
    }
    
    /**
     * See the appropriate derived class.
     * 
     * @return SignaturePublicKey
     */
    public function derivePublicKey()
    {
        $publicKey = \Sodium\crypto_box_publickey_from_secretkey(
            $this->get()
        );
        return new EncryptionPublicKey($publicKey);
    }
}
