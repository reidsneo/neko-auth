<?php namespace Neko\Auth\OAuth2\Storage\Redis;

use Neko\Auth\OAuth2\Storage\TokenInterface;
use Neko\Auth\OAuth2\Entity\Token as TokenEntity;
use Neko\Auth\OAuth2\Entity\Scope as ScopeEntity;

class Token extends Redis implements TokenInterface {

	/**
	 * Insert a token into storage.
	 * 
	 * @param  string  $token
	 * @param  string  $type
	 * @param  string  $clientId
	 * @param  mixed  $userId
	 * @param  int  $expires
	 * @return \Neko\Auth\OAuth2Entity\Token
	 */
	public function create($token, $type, $clientId, $userId, $expires)
	{
		$payload = [
			'type'      => $type,
			'client_id' => $clientId,
			'user_id'   => $userId,
			'expires'   => $expires
		];
		
		$this->setValue($token, $this->tables['tokens'], $payload);

		// Push the token onto the tokens set so that we can easily manage all
		// tokens with Redis.
		$this->pushSet(null, $this->tables['tokens'], $token);

		return new TokenEntity($token, $type, $clientId, $userId, $expires);
	}

	/**
	 * Associate scopes with a token.
	 * 
	 * @param  string  $token
	 * @param  array  $scopes
	 * @return void
	 */
	public function associateScopes($token, array $scopes)
	{
		foreach ($scopes as $scope)
		{
			$this->pushSet($token, $this->tables['token_scopes'], [
				'scope'       => $scope->getScope(),
				'name'        => $scope->getName(),
				'description' => $scope->getDescription()
			]);
		}
	}

	/**
	 * Get an access token from storage.
	 * 
	 * @param  string  $token
	 * @return \Neko\Auth\OAuth2Entity\Token|bool
	 */
	public function get($token)
	{
		if ( ! $value = $this->getValue($token, $this->tables['tokens']))
		{
			return false;
		}

		return new TokenEntity($token, $value['type'], $value['client_id'], $value['user_id'], $value['expires']);
	}

	/**
	 * Get an access token from storage.
	 * 
	 * @param  string  $token
	 * @return \Neko\Auth\OAuth2Entity\Token|bool
	 */
	public function getWithScopes($token)
	{
		if ( ! $token = $this->get($token))
		{
			return false;
		}

		$scopes = [];

		// Get the token scopes set and spin through each scope on the set
		// and create a scope entity.
		foreach ($this->getSet($token->getToken(), $this->tables['token_scopes']) as $scope)
		{
			$scopes[$scope['scope']] = new ScopeEntity($scope['scope'], $scope['name'], $scope['description']);
		}

		$token->attachScopes($scopes);

		return $token;
	}

	/**
	 * Delete an access token from storage.
	 * 
	 * @param  string  $token
	 * @return void
	 */
	public function delete($token)
	{
		$this->deleteKey($token, $this->tables['tokens']);

		$this->deleteSet(null, $this->tables['tokens'], $token);

		$this->deleteKey($token, $this->tables['token_scopes']);
	}

}