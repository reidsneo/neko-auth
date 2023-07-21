<?php namespace Neko\Auth\OAuth2\Server;

use Neko\Auth\OAuth2\Storage\Adapter;
use Neko\Auth\OAuth2\Entity\Token as TokenEntity;
use Neko\Framework\Http\Request;
use Neko\Framework\Util\Arr;
use Neko\Auth\OAuth2\Exception\InvalidTokenException;

class Resource {

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
	 * Array of default scopes.
	 * 
	 * @var array
	 */
	protected $defaultScopes = [];

	/**
	 * Authenticated access token.
	 * 
	 * @var \Neko\Auth\OAuth2Entity\Token
	 */
	protected $token;

	/**
	 * Create a new Neko\Auth\OAuth2Server\Resource instance.
	 * 
	 * @param  \Neko\Auth\OAuth2Storage\Adapter  $storage
	 * @param  \Symfony\Component\HttpFoundation\Request  $request
	 * @return void
	 */
	public function __construct(Adapter $storage, Request $request = null)
	{
		$this->storage = $storage;
		$this->request = $request;
	}

	/**
	 * Validate an access token.
	 * 
	 * @param  string|array  $scopes
	 * @return \Neko\Auth\OAuth2Entity\Token
	 * @throws \Neko\Auth\OAuth2Exception\InvalidTokenException
	 */
	public function validateRequest($scopes = null)
	{
		if ( ! $token = $this->findAccessToken())
		{
			throw new InvalidTokenException('missing_parameter', 'Access token was not supplied.', 401);
		}

		if ( ! $token = $this->storage('token')->getWithScopes($token))
		{
			throw new InvalidTokenException('unknown_token', 'Invalid access token.', 401);
		}

		if ($this->tokenHasExpired($token))
		{
			$this->storage('token')->delete($token->getToken());

			throw new InvalidTokenException('expired_token', 'Access token has expired.', 401);
		}

		$this->validateTokenScopes($token, $scopes);

		return $this->token = $token;
	}

	/**
	 * Determine if a token has expired.
	 * 
	 * @param  \Neko\Auth\OAuth2Entity\Token  $token
	 * @return bool
	 */
	protected function tokenHasExpired(TokenEntity $token)
	{
		return $token->getExpires() < time();
	}

	/**
	 * Validate token scopes.
	 * 
	 * @param  \Neko\Auth\OAuth2Entity\Token  $token
	 * @param  string|array  $scopes
	 * @return void
	 * @throws \Neko\Auth\OAuth2Exception\InvalidTokenException
	 */
	protected function validateTokenScopes(TokenEntity $token, $scopes)
	{
		// Build our array of scopes by merging the provided scopes with the
		// default scopes that are used for every request.
		$scopes = array_merge($this->defaultScopes, (array) $scopes);

		foreach ($scopes as $scope)
		{
			if ( ! $token->hasScope($scope))
			{
				throw new InvalidTokenException('mismatched_scope', 'Requested scope "'.$scope.'" is not associated with this access token.', 401);
			}
		}
	}

	/**
	 * Find the access token in either the header or request body.
	 * 
	 * @return bool|string
	 */
	public function findAccessToken()
	{
		if ($header = Arr::get($this->request->headers(),'Authorization'))
		{
			if (preg_match('/Bearer (\S+)/', $header, $matches))
			{
				list($header, $token) = $matches;

				return $token;
			}
		}
		elseif ($this->request->get('access_token'))
		{
			return $this->request->get('access_token');
		}

		return false;
	}

	/**
	 * Get the authenticated access token.
	 * 
	 * @return \Neko\Auth\OAuth2Entity\Token
	 */
	public function getToken()
	{
		return $this->token;
	}

	/**
	 * Set the default scopes.
	 * 
	 * @param  array  $scopes
	 * @return \Neko\Auth\OAuth2Server\Resource
	 */
	public function setDefaultScopes(array $scopes)
	{
		$this->defaultScopes = $scopes;

		return $this;
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