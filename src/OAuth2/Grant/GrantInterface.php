<?php namespace Neko\Auth\OAuth2\Grant;

interface GrantInterface {

	/**
	 * Get the grant identifier.
	 * 
	 * @return string
	 */
	public function getGrantIdentifier();

	/**
	 * Execute the grant flow.
	 * 
	 * @return array
	 */
	public function execute();

}