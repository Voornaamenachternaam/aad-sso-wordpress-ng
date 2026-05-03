<?php

/**
 * A helper class used to make calls to Microsoft Graph API.
 *
 * This class provides methods to interact with Microsoft Graph API.
 * When composer dependencies are installed, it can optionally use the
 * microsoft/microsoft-graph SDK for enhanced functionality.
 */
class AADSSO_GraphHelper
{
	/**
	 * @var \AADSSO_Settings|null The instance of AADSSO_Settings to use.
	 */
	public static ?AADSSO_Settings $settings = null;

	/**
	 * @var string The Graph API version to use.
	 */
	public const GRAPH_VERSION = 'v1.0';

	/**
	 * Gets the the Microsoft Graph API base URL to use.
	 *
	 * @return string The base URL to the Microsoft Graph API.
	 */
	public static function get_base_url(): string {
		$endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
		$version = self::$settings->graph_version ?? self::GRAPH_VERSION;
		return trailingslashit( $endpoint ) . $version;
	}

	/**
	 * Checks which of the given groups the given user is a member of.
	 *
	 * @param string $user_id The user ID to check.
	 * @param array<string> $group_ids The group IDs to check membership for.
	 *
	 * @return mixed The response to the checkMemberGroups request.
	 */
	public static function user_check_member_groups( string $user_id, array $group_ids ): mixed {
		$url = self::get_base_url() . '/users/' . rawurlencode( $user_id ) . '/checkMemberGroups';
		return self::post_request( $url, array(), array( 'groupIds' => $group_ids ) );
	}

	/**
	 * Gets the requested user.
	 *
	 * @param string $user_id The user ID to retrieve.
	 *
	 * @return mixed The response to the user request.
	 */
	public static function get_user( string $user_id ): mixed {
		$url = self::get_base_url() . '/users/' . rawurlencode( $user_id );
		return self::get_request( $url );
	}

	/**
	 * Issues a GET request to the Microsoft Graph API.
	 *
	 * @param string $url The URL to request.
	 * @param array<string, mixed> $query_params Query parameters to append to the URL.
	 *
	 * @return mixed The decoded response.
	 */
	public static function get_request( string $url, array $query_params = array() ): mixed {

		// Build the full query URL, adding api-version if necessary
		$query_params = http_build_query( $query_params );
		$url = $url . '?' . $query_params;

		if ( session_status() === PHP_SESSION_ACTIVE ) {
			$_SESSION['aadsso_last_request'] = array(
				'method' => 'GET',
				'url' => $url,
			);
		}

		AADSSO::debug_log( 'GET ' . $url, 50 );

		// Make the GET request
		$response = wp_remote_get( $url, array(
			'headers' => self::get_required_headers_and_settings(),
		) );

		return self::parse_and_log_response( $response );
	}

	/**
	 * Issues a POST request to the Microsoft Graph API.
	 *
	 * @param string $url The URL to request.
	 * @param array<string, mixed> $query_params Query parameters to append to the URL.
	 * @param array<string, mixed> $data The data to send in the request body.
	 *
	 * @return mixed The decoded response.
	 */
	public static function post_request( string $url, array $query_params = array(), array $data = array() ): mixed {

		// Build the full query URL and encode the payload
		$query_params = http_build_query( $query_params );
		$url = $url . '?' . $query_params;
		$payload = wp_json_encode( $data );

		AADSSO::debug_log( 'POST ' . $url, 50 );
		AADSSO::debug_log( $payload, 99 );

		// Make the POST request
		$response = wp_remote_post( $url, array(
			'body' => $payload,
			'headers' => self::get_required_headers_and_settings(),
		) );

		return self::parse_and_log_response( $response );
	}

	/**
	 * Logs the HTTP response headers and body and returns the JSON-decoded body.
	 *
	 * @param array|\WP_Error|null $response The HTTP response.
	 *
	 * @return mixed The decoded response.
	 */
	private static function parse_and_log_response( mixed $response ): mixed {

		if ( is_wp_error( $response ) ) {
			AADSSO::debug_log( 'Graph API Error: ' . $response->get_error_message(), 100 );
			return null;
		}

		if ( null === $response ) {
			return null;
		}

		$response_headers = wp_remote_retrieve_headers( $response );
		$response_body = wp_remote_retrieve_body( $response );

		AADSSO::debug_log( 'Response headers: ' . wp_json_encode( $response_headers ), 99 );
		AADSSO::debug_log( 'Response body: ' . wp_json_encode( $response_body ), 50 );

		return json_decode( $response_body );
	}

	/**
	 * Returns an array with the required headers like authorization header, service version etc.
	 *
	 * @return array<string, string> An associative array with the HTTP headers for Microsoft Graph API calls.
	 */
	private static function get_required_headers_and_settings(): array {
		// Generate the authentication header
		// Note: Session should be initialized before accessing session variables
		$token_type = $_SESSION['aadsso_token_type'] ?? 'Bearer';
		$access_token = $_SESSION['aadsso_access_token'] ?? '';
		
		return array(
			'Authorization' => $token_type . ' ' . $access_token,
			'Accept'        => 'application/json',
			'Content-Type'  => 'application/json',
			'Prefer'        => 'return-content',
		);
	}

	/**
	 * Checks if the microsoft-graph SDK is available.
	 *
	 * @return bool True if the SDK is loaded.
	 */
	public static function is_sdk_available(): bool {
		return class_exists( '\Microsoft\Graph\Graph' );
	}

	/**
	 * Creates a Microsoft Graph client instance if SDK is available.
	 *
	 * @return \Microsoft\Graph\Graph|null The Graph client or null if SDK not available.
	 */
	public static function create_graph_client(): ?\Microsoft\Graph\Graph {
		if ( ! self::is_sdk_available() ) {
			return null;
		}

		$token_type = $_SESSION['aadsso_token_type'] ?? 'Bearer';
		$access_token = $_SESSION['aadsso_access_token'] ?? '';

		$graph = new \Microsoft\Graph\Graph();
		$graph->setAccessToken( $token_type . ' ' . $access_token );

		return $graph;
	}
}
