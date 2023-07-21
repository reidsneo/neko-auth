<?php namespace Neko\Auth\OAuth2;

use Neko\Auth\OAuth2\Storage\ScopeInterface;
use Neko\Auth\OAuth2\Exception\ClientException;
use Neko\Framework\Http\Request;

class ScopeValidator {

	/**
	 * Symfony request instance.
	 * 
	 * @var \Symfony\Component\HttpFoundation\Request
	 */
	protected $request;

	/**
	 * Scope delimiter.
	 * 
	 * @var string
	 */
	protected $scopeDelimiter = ' ';

	/**
	 * Default scope if no scope was provided.
	 * 
	 * @var array|string
	 */
	protected $defaultScope;

	/**
	 * Indicates if a scope is required.
	 * 
	 * @var bool
	 */
	protected $scopeRequired = false;

	/**
	 * Create a new Neko\Auth\OAuth2ScopeValidator instance.
	 * 
	 * @param  \Symfony\Component\HttpFoundation\Request  $request
	 * @param  \Neko\Auth\OAuth2Storage\ScopeInterface  $storage
	 * @return void
	 */
	public function __construct(Request $request, ScopeInterface $storage)
	{
		$this->request = $request;
		$this->storage = $storage;
	}

	/**
	 * Validate the requested scopes. If an array of original scopes is given
	 * then it will also validate that any scopes provided exist in the
	 * original scopes (from a refresh token).
	 * 
	 * @param  array  $originalScopes
	 * @return array
	 * @throws \Neko\Auth\OAuth2Exception\ClientException
	 */
	public function validate(array $originalScopes = [])
	{
		$requestedScopes = explode($this->scopeDelimiter, $this->request->get('scope'));

		// Spin through all the scopes in the request and filter out any that
		// are blank or invalid.
		$requestedScopes = array_filter(array_map(function($scope)
		{ 
			return trim($scope);
		}, $requestedScopes));

		// If the scope parameter is required and no default scope was provided
		// or original scopes then we'll alert the client that the scope
		// parameter was missing.
		if ($this->scopeRequired and is_null($this->defaultScope) and empty($requestedScopes) and empty($originalScopes))
		{
			throw new ClientException('missing_parameter', 'The request is missing the "scope" parameter.', 400);
		}

		// If default scopes were provided and no scopes were requested then
		// we'll set the requested scopes to the default scopes.
		elseif ($this->defaultScope and empty($requestedScopes))
		{
			$requestedScopes = (array) $this->defaultScope;
		}

		// If there were original scopes provided then we'll set the requested
		// scopes to the original scopes.
		if ( ! empty($originalScopes) and empty($requestedScopes))
		{
			$requestedScopes = array_keys($originalScopes);
		}

		// If original scopes were declared for this token we'll compare the requested
		// scopes to ensure that any new scopes aren't added. If a new scope is
		// found we'll abort with an exception.
		if ( ! empty($originalScopes))
		{
			foreach ($requestedScopes as $requestedScope)
			{
				if ( ! isset($originalScopes[$requestedScope]))
				{
					throw new ClientException('suspicious_scope', 'The requested scope "'.$requestedScope.'" was not originally requested for this token.', 400);
				}
			}
		}

		$scopes = [];

		foreach ($requestedScopes as $requestedScope)
		{
			if ( ! $scope = $this->storage->get($requestedScope))
			{
				throw new ClientException('unknown_scope', 'The requested scope "'.$requestedScope.'" is invalid or unknown.', 400);
			}

			$scopes[$scope->getScope()] = $scope;
		}

		return $scopes;
	}

	/**
	 * Set the scope delimiter.
	 * 
	 * @param  string  $scopeDelimiter
	 * @return \Neko\Auth\OAuth2ScopeValidator
	 */
	public function setScopeDelimiter($scopeDelimiter)
	{
		$this->scopeDelimiter = $scopeDelimiter;

		return $this;
	}

	/**
	 * Get the scope delimiter.
	 * 
	 * @return string
	 */
	public function getScopeDelimiter()
	{
		return $this->scopeDelimiter;
	}

	/**
	 * Set the default scope.
	 * 
	 * @param  string|array  $defaultScope
	 * @return \Neko\Auth\OAuth2ScopeValidator
	 */
	public function setDefaultScope($defaultScope)
	{
		$this->defaultScope = $defaultScope;

		return $this;
	}

	/**
	 * Set the vaildator to require a scope.
	 * 
	 * @return \Neko\Auth\OAuth2ScopeValidator
	 */
	public function requireScope()
	{
		$this->scopeRequired = true;

		return $this;
	}

}