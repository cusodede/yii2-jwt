<?php

declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Signer;

class RsaVerifyTest extends SignerTestCase
{
    public $jwtConfig = ['key' => '@bizley/tests/data/rsa.key.pub'];

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return new \Lcobucci\JWT\Signer\Rsa\Sha256();
    }

    public function getSigningKey(): string
    {
        return '@bizley/tests/data/rsa.key';
    }
}
