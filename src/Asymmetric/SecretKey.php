<?php
namespace ParagonIE\Halite\Asymmetric;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Key;
use ParagonIE\HiddenString\HiddenString;
use TypeError;

/**
 * Class SecretKey
 * @package ParagonIE\Halite\Asymmetric
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
class SecretKey extends Key
{
    protected ?string $cachedPublicKey = null;

    /**
     * SecretKey constructor.
     * @param HiddenString $keyMaterial - The actual key data
     *
     * @throws TypeError
     */
    public function __construct(HiddenString $keyMaterial, ?HiddenString $pk = null)
    {
        parent::__construct($keyMaterial);
        if (!is_null($pk)) {
            $this->cachedPublicKey = $pk->getString();
        }
        $this->isAsymmetricKey = true;
    }

    /**
     * See the appropriate derived class.
     * @throws CannotPerformOperation
     * @return PublicKey
     * @codeCoverageIgnore
     */
    public function derivePublicKey(): PublicKey
    {
        throw new CannotPerformOperation(
            'This is not implemented in the base class'
        );
    }
}
