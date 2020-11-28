<?php

declare(strict_types=1);

namespace bizley\tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use yii\base\InvalidConfigException;

class HmacVerifyTest extends SignerTestCase
{
    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return new \Lcobucci\JWT\Signer\Hmac\Sha256();
    }

    /**
     * @param Builder $builder
     * @return Builder
     * @throws InvalidConfigException
     */
    public function sign(Builder $builder): Builder
    {
        return $builder->sign($this->getSigner(), $this->getJwt()->key);
    }

    /**
     * @param Token $token
     * @return bool
     * @throws InvalidConfigException
     */
    public function verify(Token $token): bool
    {
        return $token->verify($this->getSigner(), $this->getJwt()->key);
    }
}
