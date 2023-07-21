<?php namespace Neko\Auth\OAuth2;

use RuntimeException;

class Token {

	/**
	 * Make a new token.
	 * 
	 * @param  int  $length
	 * @return string
	 * @throws \RuntimeException
	 */
	public static function make($length = 40)
	{
		$randomBytes = openssl_random_pseudo_bytes($length * 2);

		if ( ! $randomBytes)
		{
			throw new RuntimeException('Failed to make a token.');
		}

		return substr(str_replace(['+', '=', '/'], '', base64_encode($randomBytes)), 0, $length);
	}

}