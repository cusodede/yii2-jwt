<?php

declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Signer;

class HmacVerifyTest extends SignerTestCase
{
    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return new \Lcobucci\JWT\Signer\Hmac\Sha256();
    }

    public function getSigningKey(): string
    {
        return $this->getJwt()->key;
    }
}
