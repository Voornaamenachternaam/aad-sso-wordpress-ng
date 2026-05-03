<?php

/**
 * A helper class used to request authorization and access tokens Microsoft Entra ID.
 */
class AADSSO_AuthorizationHelper
{
	/**
	 * @var string[] List of allowed algorithms. Currently, only RS256 is allowed and expected from AAD.
	 */
	private static array $allowed_algorithms = array( 'RS256' );

	/**
	 * Gets the authorization URL used to makes the authorization request.
	 *
	 * @param \AADSSO_Settings $settings The settings to use.
	 * @param string $antiforgery_id The value to use as the nonce.
	 *
	 * @return string The authorization URL.
	 */
	public static function get_authorization_url( $settings, string $antiforgery_id ): string {
		$auth_url = $settings->authorization_endpoint . '?'
		 . http_build_query( array(
				'response_type' => 'code',
				'scope'         => 'openid',
				'domain_hint'   => $settings->org_domain_hint,
				'client_id'     => $settings->client_id,
				'resource'      => $settings->graph_endpoint,
				'redirect_uri'  => $settings->redirect_uri,
				'state'         => $antiforgery_id,
				'nonce'         => $antiforgery_id,
			) );
		return $auth_url;
	}


	/**
	 * Exchanges an Authorization Code and obtains an Access Token and an ID Token.
	 *
	 * @param string $code The authorization code.
	 * @param \AADSSO_Settings $settings The settings to use.
	 *
	 * @return mixed The decoded authorization result.
	 */
	public static function get_access_token( string $code, $settings ) {

		// Construct the body for the access token request
		$authentication_request_body = http_build_query(
			array(
				'grant_type'    => 'authorization_code',
				'code'          => $code,
				'redirect_uri'  => $settings->redirect_uri,
				'resource'      => $settings->graph_endpoint,
				'client_id'     => $settings->client_id,
				'client_secret' => $settings->client_secret
			)
		);

		return self::get_and_process_access_token( $authentication_request_body, $settings );
	}

	/**
	 * Makes the request for the access token and some does some basic processing of the result.
	 *
	 * @param string $authentication_request_body The body to use in the Authentication Request.
	 * @param \AADSSO_Settings $settings The settings to use.
	 *
	 * @return mixed|\WP_Error The decoded authorization result or WP_Error on failure.
	 */
	public static function get_and_process_access_token( string $authentication_request_body, $settings ) {

		// Post the authorization code to the STS and get back the access token
		$response = wp_remote_post( $settings->token_endpoint, array(
			'body' => $authentication_request_body
		) );
		if( is_wp_error( $response ) ) {
			return new \WP_Error( $response->get_error_code(), $response->get_error_message() );
		}
		$output = wp_remote_retrieve_body( $response );

		// Decode the JSON response from the STS. If all went well, this will contain the access
		// token and the id_token (a JWT token telling us about the current user)
		$result = json_decode( $output );

		if ( isset( $result->access_token ) ) {

			// Add the token information to the session so that we can use it later
			// Note: Sessions should be properly initialized before this point
			if ( session_status() === PHP_SESSION_ACTIVE ) {
				$_SESSION['aadsso_token_type'] = $result->token_type;
				$_SESSION['aadsso_access_token'] = $result->access_token;
			}
		}

		return $result;
	}

	/**
	 * Decodes and validates an id_token value returned from Microsoft Entra ID.
	 *
	 * @param string $id_token The ID token to validate.
	 * @param \AADSSO_Settings $settings The settings to use.
	 * @param string $antiforgery_id The expected nonce value.
	 *
	 * @return object The decoded and validated JWT payload.
	 *
	 * @throws \DomainException If token validation fails.
	 * @throws \UnexpectedValueException If the token is invalid.
	 */
	public static function validate_id_token( string $id_token, $settings, string $antiforgery_id ): object {

		// Fetch JWKS from Microsoft
		$jwks_response = wp_remote_get( $settings->jwks_uri, array(
			'timeout' => 15,
			'sslverify' => true,
		) );
		if ( is_wp_error( $jwks_response ) ) {
			throw new \DomainException( 'Failed to fetch JWKS: ' . $jwks_response->get_error_message() );
		}
		
		$jwks_body = wp_remote_retrieve_body( $jwks_response );
		$jwks = json_decode( $jwks_body, true );

		if ( ! is_array( $jwks ) || empty( $jwks['keys'] ) ) {
			throw new \DomainException( 'jwks_uri does not contain valid keys' );
		}

		// Parse the JWKS into keys using firebase/php-jwt v7
		try {
			$keys = \Firebase\JWT\JWK::parseKeySet( $jwks, 'RS256' );
		} catch ( \Exception $e ) {
			throw new \DomainException( 'Failed to parse JWKS: ' . $e->getMessage() );
		}

		// Decode and validate the token
		try {
			$jwt = \Firebase\JWT\JWT::decode( $id_token, $keys, self::$allowed_algorithms );
		} catch ( \Firebase\JWT\ExpiredException $e ) {
			throw new \DomainException( 'Token has expired' );
		} catch ( \Firebase\JWT\SignatureInvalidException $e ) {
			throw new \DomainException( 'Token signature verification failed' );
		} catch ( \Firebase\JWT\BeforeValidException $e ) {
			throw new \DomainException( 'Token is not yet valid' );
		} catch ( \Exception $e ) {
			throw new \DomainException( 'Token validation failed: ' . $e->getMessage() );
		}

		// Validate nonce to prevent replay attacks
		if ( ! isset( $jwt->nonce ) || $jwt->nonce !== $antiforgery_id ) {
			throw new \DomainException( sprintf( 'Nonce mismatch. Expecting %s', $antiforgery_id ) );
		}

		return $jwt;
	}
}
