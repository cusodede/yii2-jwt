<?php

declare(strict_types=1);

namespace bizley\tests;

use bizley\jwt\Jwt;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;
use yii\base\InvalidConfigException;

abstract class SignerTestCase extends TestCase
{
    public $jwtConfig = [];

    /**
     * @var Jwt
     */
    protected $jwt;

    /**
     * @return Jwt
     * @throws InvalidConfigException
     */
    public function getJwt(): Jwt
    {
        if ($this->jwt === null) {
            $this->jwt = \Yii::createObject(array_merge([
                'class' => Jwt::class,
                'key' => 'secret',
            ], $this->jwtConfig));
        }

        return $this->jwt;
    }

    abstract public function getSigner(): Signer;

    abstract public function getSigningKey(): string;

    /**
     * @return Token
     * @throws InvalidConfigException
     */
    public function createTokenWithSignature(): Token
    {
        return $this->getJwt()->getBuilder()->getToken(
            $this->getSigner(),
            $this->getJwt()->prepareKeyObject($this->getSigningKey())
        );
    }

    /**
     * @throws InvalidConfigException
     * @throws \yii\base\NotSupportedException
     */
    public function testValidateTokenWithSignature(): void
    {
        self::assertTrue($this->getJwt()->verifyToken($this->createTokenWithSignature()));
    }
}
