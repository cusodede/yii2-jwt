<?php
declare(strict_types = 1);

namespace bizley\jwt;

use Closure;
use Lcobucci\JWT\UnencryptedToken;
use Throwable;
use Yii;
use yii\base\InvalidConfigException;
use yii\di\Instance;
use yii\filters\auth\HttpBearerAuth;
use yii\web\IdentityInterface;
use yii\web\Response;
use yii\web\UnauthorizedHttpException;
use yii\web\User;

/**
 * Class JwtHttpBearerAuth
 * ActionFilter, реализующий аутентификацию через Json Web Token.
 * @see https://jwt.io/
 */
class JwtHttpBearerAuth extends HttpBearerAuth
{
	/**
	 * @var string|array|Jwt id компонента, его конфигурация или сам объект компонента.
	 */
    public $jwt = 'jwt';
	/**
	 * @var string токен (payload-параметр), использующийся для идентификации пользователя в системе.
	 * По умолчанию - jti (JWT ID).
	 */
	public string $identifyClaim = 'jti';
	/**
	 * @var Closure|null анонимная функция, возвращающая пользовательскую конфигарацию компонента jwt.
	 * Если конфигурация не задана, компонент будет использовать настройки по умолчанию.
	 */
    public ?Closure $jwtOptionsCallback = null;

    /**
	 * {@inheritdoc}
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        $this->jwt = Instance::ensure($this->jwt, Jwt::class);
        
        if (empty($this->pattern)) {
            throw new InvalidConfigException('You must provide pattern to use to extract the HTTP authentication value!');
        }
    }

	/**
	 * {@inheritdoc}
	 */
    public function authenticate($user, $request, $response): ?IdentityInterface
    {
        $authHeader = $request->getHeaders()->get($this->header);

        if ((null === $authHeader) || !preg_match($this->pattern, $authHeader, $matches)) {
            return null;
        }

        try {
            $token = $this->jwt->parse($matches[1]);
        } catch (Throwable $e) {
			$token = null;
            $this->fail($response, $e);
        }

		$identity = $this->getIdentity($token, $user);
		if (null === $identity) {
			$this->fail($response);
		}

		try {
			$this->configureUserOptions($identity);

			$validateIsOk = $this->jwt->validate($token);
		} catch (Throwable $e) {
			$validateIsOk = false;
			$this->fail($response, $e);
		}

		if (!$validateIsOk || !$user->login($identity)) {
			$this->fail($response);
		}

        return $identity;
    }

	/**
	 * @param UnencryptedToken $token
	 * @param User $user
	 * @return IdentityInterface|null
	 */
    private function getIdentity(UnencryptedToken $token, User $user): ?IdentityInterface
	{
		$identifyClaim = $token->claims()->get($this->identifyClaim);
		if (null === $identifyClaim) {
			return null;
		}

		/** @var IdentityInterface $class */
		$class = $user->identityClass;

		return $class::findIdentityByAccessToken($identifyClaim, static::class);
	}

	/**
	 * @param IdentityInterface $user
	 * @throws InvalidConfigException
	 */
	private function configureUserOptions(IdentityInterface $user): void
	{
		if (null !== $this->jwtOptionsCallback) {
			$userOptions = call_user_func($this->jwtOptionsCallback, $user);
			if (is_array($userOptions) && ([] !== $userOptions)) {
				Yii::configure($this->jwt, $userOptions);
				$this->jwt->init();
			}
		}
	}

	/**
	 * @param Response $response
	 * @param Throwable|null $e
	 * @throws UnauthorizedHttpException
	 */
    private function fail(Response $response, ?Throwable $e = null): void
    {
    	if (null !== $e) {
			Yii::error($e, static::class);
		}

        $this->challenge($response);
        $this->handleFailure($response);
    }
}
