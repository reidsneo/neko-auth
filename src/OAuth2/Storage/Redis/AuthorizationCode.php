<?php namespace Neko\Auth\OAuth2\Storage\Redis;

use Neko\Auth\OAuth2\Entity\Scope as ScopeEntity;
use Neko\Auth\OAuth2\Storage\AuthorizationCodeInterface;
use Neko\Auth\OAuth2\Entity\AuthorizationCode as AuthorizationCodeEntity;

class AuthorizationCode extends Redis implements AuthorizationCodeInterface {

	/**
	 * Insert an authorization code into storage.
	 * 
	 * @param  string  $code
	 * @param  string  $clientId
	 * @param  mixed  $userId
	 * @param  string  $redirectUri
	 * @param  int  $expires
	 * @return \Neko\Auth\OAuth2Entity\AuthorizationCode
	 */
	public function create($code, $clientId, $userId, $redirectUri, $expires)
	{
		$payload = [
			'client_id'    => $clientId,
			'user_id'      => $userId,
			'redirect_uri' => $redirectUri,
			'expires'      => $expires
		];

		$this->setValue($code, $this->tables['authorization_codes'], $payload);

		// Push the authorization code onto the authorization codes set so that
		// we can easily manage all authorization codes with Redis.
		$this->pushSet(null, $this->tables['authorization_codes'], $code);

		return new AuthorizationCodeEntity($code, $clientId, $userId, $redirectUri, $expires);
	}

	/**
	 * Associate scopes with an authorization code.
	 * 
	 * @param  string  $code
	 * @param  array  $scopes
	 * @return void
	 */
	public function associateScopes($code, array $scopes)
	{
		foreach ($scopes as $scope)
		{
			$this->pushSet($code, $this->tables['authorization_code_scopes'], [
				'scope'       => $scope->getScope(),
				'name'        => $scope->getName(),
				'description' => $scope->getDescription()
			]);
		}
	}

	/**
	 * Get a code from storage.
	 * 
	 * @param  string  $code
	 * @return \Neko\Auth\OAuth2Entity\AuthorizationCode
	 */
	public function get($code)
	{
		if ( ! $value = $this->getValue($code, $this->tables['authorization_codes']))
		{
			return false;
		}

		$code = new AuthorizationCodeEntity($code, $value['client_id'], $value['user_id'], $value['redirect_uri'], $value['expires']);

		$scopes = [];

		// Get the authorization code scopes set and spin through each scope
		// on the set and create a scope entity.
		foreach ($this->getSet($code->getCode(), $this->tables['authorization_code_scopes']) as $scope)
		{
			$scopes[$scope['scope']] = new ScopeEntity($scope['scope'], $scope['name'], $scope['description']);
		}

		$code->attachScopes($scopes);

		return $code;
	}

	/**
	 * Delete an authorization code from storage.
	 * 
	 * @param  string  $code
	 * @return void
	 */
	public function delete($code)
	{
		$this->deleteKey($code, $this->tables['authorization_codes']);

		$this->deleteSet(null, $this->tables['authorization_codes'], $code);

		$this->deleteKey($code, $this->tables['authorization_code_scopes']);
	}

}