<?php

declare(strict_types=1);

namespace bizley\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\NoConstraintsGiven;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

use function in_array;
use function is_array;
use function is_string;
use function strpos;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v4.
 * @see https://github.com/lcobucci/jwt
 *
 * @author Paweł Bizley Brzozowski <pawel@positive.codes> since 2.0 (fork)
 * @author Dmitriy Demin <sizemail@gmail.com> original package
 */
class Jwt extends Component
{
    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';
    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';

    public const STORE_IN_MEMORY = 'in_memory';
    public const STORE_LOCAL_FILE_REFERENCE = 'local_file_reference';

    public const METHOD_PLAIN = 'plain';
    public const METHOD_BASE64 = 'base64';
    public const METHOD_FILE = 'file';

    private const SYMMETRIC = 'symmetric';
    private const ASYMMETRIC = 'asymmetric';

    private const KEY = 'key';
    private const STORE = 'store';
    private const METHOD = 'method';
    private const PASSPHRASE = 'passphrase';

    /**
     * @var string|array|Key Signing key definition.
     * This can be a simple string, an instance of Key interface, or a configuration array.
     * The configuration takes the following array keys:
     * - 'key'        => Key's value or path to the key file.
     * - 'store'      => Either `Jwt::STORE_IN_MEMORY` or `Jwt::STORE_LOCAL_FILE_REFERENCE` - whether to keep the key in
     *                   the memory or as a reference to a local file.
     * - 'method'     => `Jwt::METHOD_PLAIN`, `Jwt::METHOD_BASE64`, or `Jwt::METHOD_FILE` - whether the key is a plain
     *                   text, base64 encoded text, or a file.
     *                   In case the 'store' is set to `Jwt::STORE_LOCAL_FILE_REFERENCE`, only `Jwt::METHOD_FILE` method
     *                   is available.
     * - 'passphrase' => Key's passphrase.
     * In case a simple string is provided (and it does not start with 'file://' or '@') the following configuration
     * is assumed:
     * [
     *  'key' => // the original given value,
     *  'store' => Jwt::STORE_IN_MEMORY,
     *  'method' => Jwt::METHOD_PLAIN,
     *  'passphrase' => '',
     * ]
     * In case a simple string is provided and it does start with 'file://' (direct file path) or '@' (Yii alias)
     * the following configuration is assumed:
     * [
     *  'key' => // the original given value,
     *  'store' => Jwt::STORE_IN_MEMORY,
     *  'method' => Jwt::METHOD_FILE,
     *  'passphrase' => '',
     * ]
     * If you want to override the assumed configuration, you must provide it directly.
     * @since 3.0.0
     */
    public $signingKey = '';

    /**
     * @var string|array|Key Verifying key definition.
     * $signingKey documentation you can find above applies here as well.
     * Symmetric algorithms (like HMAC) use a single key to sign and verify tokens so this property is ignored in that
     * case. Asymmetric algorithms (like RSA and ECDSA) use a private key to sign and a public key to verify.
     * @since 3.0.0
     */
    public $verifyingKey = '';

    /**
     * @var string|Signer|null Signer ID or Signer instance to be used for signing/verifying.
     * See $signers for available values. In case it's not set, no algorithm will be used, which may be handy if you want
     * to do some testing but it's NOT recommended for production environments.
     * @since 3.0.0
     */
    public ?string $signer = null;

    /**
     * @var array Token signers
     * @since 2.0.0
     */
    public array $signers = [
        self::HS256 => Signer\Hmac\Sha256::class,
        self::HS384 => Signer\Hmac\Sha384::class,
        self::HS512 => Signer\Hmac\Sha512::class,
        self::RS256 => Signer\Rsa\Sha256::class,
        self::RS384 => Signer\Rsa\Sha384::class,
        self::RS512 => Signer\Rsa\Sha512::class,
        self::ES256 => Signer\Ecdsa\Sha256::class,
        self::ES384 => Signer\Ecdsa\Sha384::class,
        self::ES512 => Signer\Ecdsa\Sha512::class,
    ];

    /**
     * @var array Algorithm types.
     * @since 3.0.0
     */
    public array $algorithmTypes = [
        self::SYMMETRIC => [
            self::HS256,
            self::HS384,
            self::HS512,
        ],
        self::ASYMMETRIC => [
            self::RS256,
            self::RS384,
            self::RS512,
            self::ES256,
            self::ES384,
            self::ES512,
        ],
    ];

    /**
     * @var string|array|Encoder|null Custom encoder.
     * It can be component's ID, configuration array, or instance of Encoder.
     * In case it's not an instance, it must be resolvable to an Encoder's instance.
     * @since 3.0.0
     */
    public $encoder;

    /**
     * @var string|array|Decoder|null Custom decoder.
     * It can be component's ID, configuration array, or instance of Decoder.
     * In case it's not an instance, it must be resolvable to a Decoder's instance.
     * @since 3.0.0
     */
    public $decoder;

    private ?Configuration $configuration = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        if ($this->encoder !== null) {
            $this->encoder = Instance::ensure($this->encoder, Encoder::class);
        }
        if ($this->decoder !== null) {
            $this->decoder = Instance::ensure($this->decoder, Decoder::class);
        }

        if ($this->signer === null) {
            $this->configuration = Configuration::forUnsecuredSigner($this->encoder, $this->decoder);
        } else {
            $signerId = $this->signer;
            if ($this->signer instanceof Signer) {
                $signerId = $this->signer->algorithmId();
            }
            if (in_array($signerId, $this->algorithmTypes[self::SYMMETRIC], true)) {
                $this->configuration = Configuration::forSymmetricSigner(
                    $this->prepareSigner($this->signer),
                    $this->prepareKey($this->signingKey),
                    $this->encoder,
                    $this->decoder
                );
            } elseif (in_array($signerId, $this->algorithmTypes[self::ASYMMETRIC], true)) {
                $this->configuration = Configuration::forAsymmetricSigner(
                    $this->prepareSigner($this->signer),
                    $this->prepareKey($this->signingKey),
                    $this->prepareKey($this->verifyingKey),
                    $this->encoder,
                    $this->decoder
                );
            } else {
                throw new InvalidConfigException('Invalid signer ID!');
            }
        }

        parent::init();
    }

    /**
     * @since 3.0.0
     */
    public function getConfiguration(): Configuration
    {
        return $this->configuration;
    }

    /**
     * Since 3.0.0 this method is using different signature.
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/issuing-tokens/ for details of using the builder.
     */
    public function getBuilder(?ClaimsFormatter $claimFormatter = null): Builder
    {
        return $this->getConfiguration()->builder($claimFormatter);
    }

    /**
     * Since 3.0.0 this method is using different signature.
     * @see https://lcobucci-jwt.readthedocs.io/en/latest/parsing-tokens/ for details of using the parser.
     */
    public function getParser(): Parser
    {
        return $this->getConfiguration()->parser();
    }

    /**
     * @throws CannotDecodeContent When something goes wrong while decoding.
     * @throws InvalidTokenStructure When token string structure is invalid.
     * @throws UnsupportedHeaderFound When parsed token has an unsupported header.
     * @since 3.0.0
     */
    public function parse(string $jwt): Token
    {
        return $this->getParser()->parse($jwt);
    }

    /**
     * This method goes through every single constraint in the set, groups all the violations, and throws an exception
     * with the grouped violations.
     * @param string|Token $jwt JWT string or instance of Token
     * @throws RequiredConstraintsViolated When constraint is violated
     * @throws NoConstraintsGiven When no constraints are provided
     * @since 3.0.0
     */
    public function assert($jwt): void
    {
        $configuration = $this->getConfiguration();
        if ($jwt instanceof Token) {
            $token = $jwt;
        } else {
            $token = $this->parse($jwt);
        }
        $constraints = $configuration->validationConstraints();
        $configuration->validator()->assert($token, ...$constraints);
    }

    /**
     * This method return false on first constraint violation
     * @param string|Token $jwt JWT string or instance of Token
     * @since 3.0.0
     */
    public function validate($jwt): bool
    {
        $configuration = $this->getConfiguration();
        if ($jwt instanceof Token) {
            $token = $jwt;
        } else {
            $token = $this->parse($jwt);
        }
        $constraints = $configuration->validationConstraints();

        return $configuration->validator()->validate($token, ...$constraints);
    }

    /**
     * Prepares key based on the definition.
     * @param string|array|Key $key
     * @return Key
     * @throws InvalidConfigException
     * @since 2.0.0
     * Since 3.0.0 this method is private and using different signature.
     */
    private function prepareKey($key): Key
    {
        if ($key instanceof Key) {
            return $key;
        }

        if (is_string($key)) {
            if (strpos($key, '@') === 0) {
                $keyConfig = [
                    self::KEY => 'file://' . Yii::getAlias($key),
                    self::STORE => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_FILE,
                ];
            } elseif (strpos($key, 'file://') === 0) {
                $keyConfig = [
                    self::KEY => $key,
                    self::STORE => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_FILE,
                ];
            } else {
                $keyConfig = [
                    self::KEY => $key,
                    self::STORE => self::STORE_IN_MEMORY,
                    self::METHOD => self::METHOD_PLAIN,
                ];
            }
        } elseif (is_array($key)) {
            $keyConfig = $key;
        } else {
            throw new InvalidConfigException('Invalid key configuration!');
        }

        $value = $keyConfig[self::KEY] ?? '';
        $store = $keyConfig[self::STORE] ?? self::STORE_IN_MEMORY;
        $method = $keyConfig[self::METHOD] ?? self::METHOD_PLAIN;
        $passphrase = $keyConfig[self::PASSPHRASE] ?? '';

        if (!is_string($value)) {
            throw new InvalidConfigException('Invalid key value!');
        }
        if (!in_array($store, [self::STORE_IN_MEMORY, self::STORE_LOCAL_FILE_REFERENCE], true)) {
            throw new InvalidConfigException('Invalid key store!');
        }
        if (!in_array($method, [self::METHOD_PLAIN, self::METHOD_BASE64, self::METHOD_FILE], true)) {
            throw new InvalidConfigException('Invalid key method!');
        }
        if (!is_string($passphrase)) {
            throw new InvalidConfigException('Invalid key passphrase!');
        }

        switch (true) {
            case $store === self::STORE_IN_MEMORY && $method === self::METHOD_PLAIN:
                return Key\InMemory::plainText($value, $passphrase);
            case $store === self::STORE_IN_MEMORY && $method === self::METHOD_BASE64:
                return Key\InMemory::base64Encoded($value, $passphrase);
            case $store === self::STORE_IN_MEMORY && $method === self::METHOD_FILE:
                return Key\InMemory::file($value, $passphrase);
            case $store === self::STORE_LOCAL_FILE_REFERENCE && $method === self::METHOD_FILE:
                return Key\LocalFileReference::file($value, $passphrase);
            default:
                throw new InvalidConfigException('Invalid key store and method combination!');
        }
    }

    /**
     * @param string|Signer $signer
     * @return Signer
     * @throws InvalidConfigException
     */
    private function prepareSigner($signer): Signer
    {
        if ($signer instanceof Signer) {
            return $signer;
        }

        /** @var Signer $signerInstance */
        $signerInstance = Yii::createObject($this->signers[$signer]);

        return $signerInstance;
    }
}
