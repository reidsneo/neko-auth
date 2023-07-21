<?php namespace Neko\Auth\OAuth2\Entity;

class Scope extends Entity {

	/**
	 * Create a new Neko\Auth\OAuth2Entity\Scope instance.
	 * 
	 * @param  string  $scope
	 * @param  string  $name
	 * @param  string  $description
	 * @return void
	 */
	public function __construct($scope, $name = null, $description = null)
	{
		$this->scope = $scope;
		$this->name = $name;
		$this->description = $description;
	}

}