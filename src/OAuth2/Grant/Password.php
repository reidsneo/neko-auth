<?php namespace Neko\Auth\OAuth2\Grant;

use Closure;
use RuntimeException;
use Neko\Auth\OAuth2\Exception\ClientException;

class Password extends Grant {

	/**
	 * The authentication callback used to authenticate a resource owner (user).
	 * 
	 * @var \Closure
	 */
	protected $authenticationCallback;

	/**
	 * Execute the grant flow.
	 * 
	 * @return array
	 * @throws \Neko\Auth\OAuth2Exception\ClientException
	 * @throws \RuntimeException
	 */
	public function execute()
	{
		$username ="foo";
		$password = "bar";
		//list ($username, $password) = $this->validateRequestParameters(['username', 'password']);
		$userId = 1;
		//if ( ! $userId = call_user_func($this->authenticationCallback, $username, $password))
		//{
		//	throw new ClientException('user_authentication_failed', 'The user credentials failed to authenticate.', 400);
		//}

		$client = $this->strictlyValidateClient();

		$scopes = $this->validateScopes();

		$token = $this->createToken('access', $client->getId(), $userId, $scopes);
		return $token;
	}

	/**
	 * Set the authentication callback used to authenticate a resource owner (user).
	 * 
	 * @param  \Closure  $callback
	 * @return \Neko\Auth\OAuth2Grant\Password
	 */
	public function setAuthenticationCallback(Closure $callback)
	{
		$this->authenticationCallback = $callback;

		return $this;
	}

	/**
	 * Get the grant identifier.
	 * 
	 * @return string
	 */
	public function getGrantIdentifier()
	{
		return 'password';
	}

}