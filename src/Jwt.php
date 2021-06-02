<?php

declare(strict_types = 1);

namespace bizley\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Lcobucci\JWT\Signer\Ecdsa\SignatureConverter;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Yii;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;

/**
 * JSON Web Token implementation based on lcobucci/jwt library v4.
 * @see https://github.com/lcobucci/jwt
 *
 * @property-read Parser $parser
 */
class Jwt extends Component
{
	public const HS256 = Signer\Hmac\Sha256::class;
	public const HS384 = Signer\Hmac\Sha384::class;
	public const HS512 = Signer\Hmac\Sha512::class;
	public const RS256 = Signer\Rsa\Sha256::class;
	public const RS384 = Signer\Rsa\Sha384::class;
	public const RS512 = Signer\Rsa\Sha512::class;
	public const ES256 = Signer\Ecdsa\Sha256::class;
	public const ES384 = Signer\Ecdsa\Sha384::class;
	public const ES512 = Signer\Ecdsa\Sha512::class;

	public const ALGORITHM_TYPE_SYMMETRIC  = 'symmetric';
	public const ALGORITHM_TYPE_ASYMMETRIC = 'asymmetric';

	/**
	 * @var array Algorithm types.
	 */
	public array $algorithmTypes = [
		self::HS256 => self::ALGORITHM_TYPE_SYMMETRIC,
		self::HS384 => self::ALGORITHM_TYPE_SYMMETRIC,
		self::HS512 => self::ALGORITHM_TYPE_SYMMETRIC,
		self::RS256 => self::ALGORITHM_TYPE_ASYMMETRIC,
		self::RS384 => self::ALGORITHM_TYPE_ASYMMETRIC,
		self::RS512 => self::ALGORITHM_TYPE_ASYMMETRIC,
		self::ES256 => self::ALGORITHM_TYPE_ASYMMETRIC,
		self::ES384 => self::ALGORITHM_TYPE_ASYMMETRIC,
		self::ES512 => self::ALGORITHM_TYPE_ASYMMETRIC,
	];

	/**
	 * @var string|array|Signer|null конфигурация компонента подписи.
	 * Если задано `null` значение, то будет использована unsecured конфигурация.
	 */
	public $signer = self::HS256;
	/**
	 * @var string|array|Key конфигурация ключа подписи.
	 */
	public $signerKey = '';
	/**
	 * @var string|array|Key конфигурация ключа верификации.
	 * При использовании симметричного алгоритма подписи свойство игнорируется.
	 */
	public $verifyKey = '';
	/**
	 * @var string|array|Encoder Custom encoder.
	 */
	public $encoder = JoseEncoder::class;
	/**
	 * @var string|array|Decoder Custom decoder.
	 */
	public $decoder = JoseEncoder::class;
	/**
	 * @var array|Constraint[] список валидаторов для проверки токена.
	 * Требуется задать, как минимум, один валидатор.
	 * Также, при конфигурации массив будт дополняться "must have" валидаторами.
	 * @see configureConstraints()
	 */
	public array $validationConstraints = [];

	/**
	 * @var Configuration|null
	 */
	private ?Configuration $_configuration = null;

	/**
	 * @throws InvalidConfigException
	 */
	public function init(): void
	{
		parent::init();

		$this->initEncoders();
		if ($this->signer === null) {
			$this->_configuration = Configuration::forUnsecuredSigner($this->encoder, $this->decoder);
		} else {
			$this->initSigner();
			$this->initKey($this->signerKey);
			$this->initKey($this->verifyKey);

			$this->initConfiguration();
		}
	}

	/**
	 * @param string $jwt
	 * @return UnencryptedToken
	 */
	public function parse(string $jwt): UnencryptedToken
	{
		return $this->parser->parse($jwt);
	}

	/**
	 * @param ClaimsFormatter|null $claimFormatter
	 * @return Builder
	 */
	public function getBuilder(?ClaimsFormatter $claimFormatter = null): Builder
	{
		return $this->_configuration->builder($claimFormatter);
	}

	/**
	 * @return Parser
	 */
	public function getParser(): Parser
	{
		return $this->_configuration->parser();
	}

	/**
	 * @param Token $token
	 */
	public function assert(Token $token): void
	{
		$this->_configuration->validator()->assert($token, ...$this->_configuration->validationConstraints());
	}

	/**
	 * @param Token $token
	 * @return bool
	 */
	public function validate(Token $token): bool
	{
		return $this->_configuration->validator()->validate($token, ...$this->_configuration->validationConstraints());
	}

	/**
	 * @throws InvalidConfigException
	 */
	private function initConfiguration(): void
	{
		$algorithm = $this->algorithmTypes[get_class($this->signer)] ?? null;

		if ($algorithm === self::ALGORITHM_TYPE_SYMMETRIC) {
			$this->_configuration = Configuration::forSymmetricSigner(
				$this->signer,
				$this->signerKey,
				$this->encoder,
				$this->decoder
			);
		} elseif ($algorithm === self::ALGORITHM_TYPE_ASYMMETRIC) {
			$this->_configuration = Configuration::forAsymmetricSigner(
				$this->signer,
				$this->signerKey,
				$this->verifyKey,
				$this->encoder,
				$this->decoder
			);
		} else {
			throw new InvalidConfigException('Invalid signer ID!');
		}

		$this->configureConstraints();
	}

	/**
	 * @throws InvalidConfigException
	 */
	private function initSigner(): void
	{
		//применимо только для Ecdsa
		Yii::$container->set(SignatureConverter::class, MultibyteStringConverter::class);

		$this->signer = Instance::ensure($this->signer, Signer::class);
	}

	/**
	 * @throws InvalidConfigException
	 */
	private function initEncoders(): void
	{
		$this->encoder = Instance::ensure($this->encoder, Encoder::class);
		$this->decoder = Instance::ensure($this->decoder, Encoder::class);
	}

	/**
	 * @param mixed $key
	 * @throws InvalidConfigException
	 */
	private function initKey(&$key): void
	{
		if ('' === $key) {
			return;
		}

		if (is_string($key)) {
			if (strpos($key, '@') === 0) {
				$key = LocalFileReference::file(Yii::getAlias($key));
			} elseif (strpos($key, 'file://') === 0) {
				$key = LocalFileReference::file($key);
			} else {
				$key = InMemory::plainText($key);
			}
		} else {
			$key = Instance::ensure($key, Key::class);
		}
	}

	/**
	 * @throws InvalidConfigException
	 */
	private function configureConstraints(): void
	{
		if ([] === $this->validationConstraints) {
			$this->validationConstraints[] = new SignedWith(
				$this->_configuration->signer(),
				$this->_configuration->verificationKey()
			);
		}

		$constraints = array_map(
			static function ($constraint) {
				return Instance::ensure($constraint, Constraint::class);
			},
			$this->validationConstraints
		);

		$this->_configuration->setValidationConstraints(...$constraints);
	}
}
