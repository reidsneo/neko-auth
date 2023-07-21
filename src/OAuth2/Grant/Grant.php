<?php namespace Neko\Auth\OAuth2\Grant;

use Neko\Auth\OAuth2\Token;
use Neko\Auth\OAuth2\ScopeValidator;
use Neko\Auth\OAuth2\Storage\Adapter;
use Neko\Auth\OAuth2\Exception\ClientException;
use Neko\Auth\OAuth2\Entity\Token as TokenEntity;
use Neko\Framework\Http\Request;

abstract class Grant implements GrantInterface {

	/**
	 * Storage adapter instance.
	 * 
	 * @var \Neko\Auth\OAuth2Storage\Adapter
	 */
	protected $storage;

	/**
	 * Symfony request instance.
	 * 
	 * @var \Symfony\Component\HttpFoundation\Request
	 */
	protected $request;

	/**
	 * Scope validator instance.
	 * 
	 * @var \Neko\Auth\OAuth2ScopeValidator
	 */
	protected $scopeValidator;

	/**
	 * Access token expiration in seconds.
	 * 
	 * @var int
	 */
	protected $accessTokenExpiration;

	/**
	 * Refresh token expiration in seconds.
	 * 
	 * @var int
	 */
	protected $refreshTokenExpiration;

	/**
	 * Validate a client. If strictly validating an ID and secret are required.
	 * 
	 * @param  bool  $strict
	 * @return \Neko\Auth\OAuth2Entity\Client
	 * @throws \Neko\Auth\OAuth2Exception\ClientException
	 */ 
	protected function validateClient($strict = false)
	{
		// Grab the redirection URI from the post data if there is one. This is
		// sent along when validating a client for some grant types. It doesn't
		// matter if we send along a "null" value though.
		$redirectUri = $this->request->get('redirect_uri');
		
		$id = $this->request->get('client_id');

		$secret = $this->request->get('client_secret');

		// If we have a client ID and secret we'll attempt to verify the client by
		// grabbing its details from the storage adapter.
		if (( ! $strict or ($strict and $id and $secret)) and $client = $this->storage('client')->get($id, $secret, $redirectUri))
		{
			return $client;
		}

		throw new ClientException('client_authentication_failed', 'The client failed to authenticate.', 401);
	}

	/**
	 * Strictly validate a client.
	 * 
	 * @param  bool  $strict
	 * @return \Neko\Auth\OAuth2Entity\Client
	 * @throws \Neko\Auth\OAuth2Exception\ClientException
	 */
	protected function strictlyValidateClient()
	{
		return $this->validateClient(true);
	}

	/**
	 * Validate the requested scopes.
	 * 
	 * @param  array  $originalScopes
	 * @return array
	 */
	protected function validateScopes(array $originalScopes = [])
	{
		return $this->scopeValidator->validate($originalScopes);
	}

	/**
	 * Validate that the request includes given parameters.
	 * 
	 * @param  array  $parameters
	 * @return array
	 * @throws \Neko\Auth\OAuth2Exception\ClientException
	 */
	protected function validateRequestParameters(array $parameters)
	{
		$values = [];

		foreach ($parameters as $parameter)
		{
			if ( ! $this->request->get($parameter))
			{
				throw new ClientException('missing_parameter', 'The request is missing the "'.$parameter.'" parameter.', 400);
			}

			$values[] = $this->request->get($parameter);
		}

		return $values;
	}

	/**
	 * Create a new token in the storage.
	 * 
	 * @param  string  $type
	 * @param  string  $clientId
	 * @param  mixed  $userId
	 * @param  array  $scopes
	 * @return \Neko\Auth\OAuth2Entity\Token
	 */
	protected function createToken($type, $clientId, $userId, array $scopes = [])
	{
		$token = $this->generateToken();

		$expires = time() + $this->{$type.'TokenExpiration'};

		$token = $this->storage('token')->create($token, $type, $clientId, $userId, $expires);

		if ($scopes)
		{
			$this->storage('token')->associateScopes($token->getToken(), $scopes);

			$token->attachScopes($scopes);
		}

		return $token;
	}

	/**
	 * Generate a new token.
	 * 
	 * @return string
	 */
	public function generateToken()
	{
		return Token::make();
	}

	/**
	 * Set the storage adapter instance.
	 * 
	 * @param  \Neko\Auth\OAuth2Storage\Adapter  $storage
	 * @return \Neko\Auth\OAuth2Grant\Grant
	 */
	public function setStorage(Adapter $storage)
	{
		$this->storage = $storage;

		return $this;
	}

	/**
	 * Set the symfony request instance.
	 * 
	 * @param  \Symfony\Component\HttpFoundation\Request  $request
	 * @return \Neko\Auth\OAuth2Grant\Grant
	 */
	public function setRequest(Request $request)
	{
		$this->request = $request;

		return $this;
	}

	/**
	 * Set the scope validator instance.
	 * 
	 * @param  \Neko\Auth\OAuth2ScopeValidator  $scopeValidator
	 * @return \Neko\Auth\OAuth2Grant\Grant
	 */
	public function setScopeValidator(ScopeValidator $scopeValidator)
	{
		$this->scopeValidator = $scopeValidator;

		return $this;
	}

	/**
	 * Set the access token expiration time in seconds.
	 * 
	 * @param  int  $expires
	 * @return \Neko\Auth\OAuth2Grant\Grant
	 */
	public function setAccessTokenExpiration($expires)
	{
		$this->accessTokenExpiration = $expires;

		return $this;
	}

	/**
	 * Set the refresh token expiration time in seconds.
	 * 
	 * @param  int  $expires
	 * @return \Neko\Auth\OAuth2Grant\Grant
	 */
	public function setRefreshTokenExpiration($expires)
	{
		$this->refreshTokenExpiration = $expires;

		return $this;
	}

	/**
	 * Get the access token expiration time in seconds.
	 * 
	 * @return int
	 */
	public function getAccessTokenExpiration()
	{
		return $this->accessTokenExpiration;
	}

	/**
	 * Get the refresh token expiration time in seconds.
	 * 
	 * @return int
	 */
	public function getRefreshTokenExpiration()
	{
		return $this->accessTokenExpiration;
	}

	/**
	 * Get the response type.
	 * 
	 * @return string
	 */
	public function getResponseType()
	{
		return null;
	}

	/**
	 * Get a specific storage from the storage adapter.
	 * 
	 * @param  string  $storage
	 * @return mixed
	 */
	public function storage($storage)
	{
		return $this->storage->get($storage);
	}

}