<?php

declare(strict_types=1);

use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Graph\Core\Authentication\GraphPhpLeagueAuthenticationProvider;
use Microsoft\Graph\{GraphPhpLeagueAccessTokenProvider, GraphServiceClient};
use Microsoft\Graph\Models\ODataErrors\ODataError;
use Microsoft\Kiota\Authentication\Cache\InMemoryAccessTokenCache;
use Microsoft\Kiota\Authentication\Oauth\TokenRequestContext;

/**
 * Microsoft Graph API helper using the official Microsoft Graph SDK.
 *
 * This helper wraps the microsoft/microsoft-graph SDK (v3.1.0+) to provide
 * type-safe access to Microsoft Graph API endpoints used for user and
 * group membership operations.
 *
 * Benefits of using the official SDK:
 * - Production-tested, Microsoft-maintained code
 * - Proper HTTP transport handling
 * - Type-safe models with IDE autocomplete
 * - Consistent error handling via ODataError
 * - Better timeout and retry configuration
 */
class GraphHelper
{
    public const GRAPH_VERSION = 'v1.0';

    public static ?AADSSO_Settings $settings = null;

    /**
     * Get the configured Graph API base URL.
     *
     * @return string The base URL (e.g., https://graph.microsoft.com/v1.0)
     */
    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;

        return trailingslashit($endpoint) . $version;
    }

    /**
     * Get a user by their ID (Object ID from Entra ID).
     *
     * @see https://docs.microsoft.com/en-us/graph/api/user-get
     *
     * @param string $user_id The user's Object ID (GUID)
     *
     * @return object|WP_Error The user object or WP_Error on failure
     */
    public static function get_user(string $user_id): object|WP_Error
    {
        $access_token = self::get_access_token();
        if ('' === $access_token) {
            return new WP_Error(
                'missing_access_token',
                'No access token available for Graph API request'
            );
        }

        try {
            $client = self::get_graph_client($access_token);
            $user = $client->users()->byUserId($user_id)->get()->wait();

            if (null === $user) {
                return new WP_Error(
                    'user_not_found',
                    'User not found or Graph API returned null'
                );
            }

            // Convert to plain object for backward compatibility
            return self::user_to_object($user);
        } catch (ODataError $e) {
            $error = $e->getError();
            $error_code = $error?->getCode();
            $error_message = $error?->getMessage() ?? $e->getMessage();
            AADSSO_Logger::log_error('Graph API get_user error: ' . ($error_code ?? 'unknown') . ' - ' . $error_message);

            return new WP_Error(
                'graph_api_error',
                'Failed to get user from Graph API: ' . $error_message
            );
        } catch (Throwable $e) {
            AADSSO_Logger::log_error('Graph API get_user exception: ' . $e->getMessage());

            return new WP_Error(
                'http_request_failed',
                'Graph API request failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Check if a user is a member of the specified groups.
     *
     * @see https://docs.microsoft.com/en-us/graph/api/user-checkmembergroups
     *
     * @param list<string> $group_ids List of group IDs to check membership for
     *
     * @return object|WP_Error Object with 'value' property containing array of group IDs the user is a member of,
     *                         or WP_Error on failure
     */
    public static function user_check_member_groups(string $user_id, array $group_ids): object|WP_Error
    {
        $access_token = self::get_access_token();
        if ('' === $access_token) {
            return new WP_Error(
                'missing_access_token',
                'No access token available for Graph API request'
            );
        }

        try {
            $client = self::get_graph_client($access_token);

            // Build the request body with group IDs
            $body = new Microsoft\Graph\Users\Item\CheckMemberGroups\CheckMemberGroupsPostRequestBody([
                'groupIds' => $group_ids,
            ]);

            $result = $client->users()->byUserId($user_id)->checkMemberGroups()->post($body)->wait();

            if (null === $result) {
                return (object) ['value' => []];
            }

            // Get the value array from the response
            $result_value = $result->getValue();
            $value = \is_array($result_value) ? $result_value : [];

            return (object) ['value' => $value];
        } catch (ODataError $e) {
            $error = $e->getError();
            $error_code = $error?->getCode();
            $error_message = $error?->getMessage() ?? $e->getMessage();
            AADSSO_Logger::log_error('Graph API checkMemberGroups error: ' . ($error_code ?? 'unknown') . ' - ' . $error_message);

            return new WP_Error(
                'graph_api_error',
                'Failed to check group membership: ' . $error_message
            );
        } catch (Throwable $e) {
            AADSSO_Logger::log_error('Graph API checkMemberGroups exception: ' . $e->getMessage());

            return new WP_Error(
                'http_request_failed',
                'Graph API request failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Get GraphServiceClient instance configured with an existing access token.
     *
     * This method uses the Microsoft Graph SDK's InMemoryAccessTokenCache to
     * store the pre-existing access token from our OAuth flow. The SDK handles
     * HTTP transport, authentication headers, and response serialization.
     *
     * The token provider chain:
     * 1. InMemoryAccessTokenCache - stores the OAuth token
     * 2. GraphPhpLeagueAccessTokenProvider - retrieves tokens from cache
     * 3. GraphPhpLeagueAuthenticationProvider - wraps for GraphServiceClient
     *
     * @param string $access_token The OAuth access token (Bearer token from token endpoint)
     *
     * @return GraphServiceClient Configured Graph client ready for API calls
     */
    private static function get_graph_client(string $access_token): GraphServiceClient
    {
        // Scopes required for Graph API access (same as used during token acquisition)
        $scopes = [
            'https://graph.microsoft.com/User.Read',
            'https://graph.microsoft.com/GroupMember.Read.All',
        ];

        // Create a TokenRequestContext with the required scopes
        // The SDK uses this to identify which token in the cache to use for requests
        $token_request_context = new TokenRequestContext($scopes);

        // Parse token expiry from the session
        // Token expires_at is stored as Unix timestamp
        $expires_at = self::get_token_expires_at();
        $expires_in = 0;
        if ($expires_at > 0) {
            $expires_in = max(0, $expires_at - time());
        }

        // Create an AccessToken object with the OAuth token data
        // The SDK's AccessToken wraps the oauth2-client AccessToken
        $access_token_obj = new AccessToken([
            'access_token' => $access_token,
            'refresh_token' => self::get_refresh_token(),
            'expires' => $expires_in,
        ]);

        // Create an in-memory cache to store the token
        // The SDK will use this cached token for all Graph API requests
        $token_cache = new InMemoryAccessTokenCache($token_request_context, $access_token_obj);

        // Create the access token provider with the cache
        // This provider will automatically retrieve tokens from the cache
        $access_token_provider = GraphPhpLeagueAccessTokenProvider::createWithCache(
            $token_cache,
            $token_request_context,
            $scopes
        );

        // Wrap with GraphPhpLeagueAuthenticationProvider for GraphServiceClient compatibility
        $authentication_provider = GraphPhpLeagueAuthenticationProvider::createWithAccessTokenProvider(
            $access_token_provider
        );

        // Create and return the Graph client with the authentication provider
        return GraphServiceClient::createWithAuthenticationProvider($authentication_provider);
    }

    /**
     * Get access token from session.
     *
     * @return string The access token or empty string if not available
     */
    private static function get_access_token(): string
    {
        if (\PHP_SESSION_ACTIVE === session_status()) {
            $token = $_SESSION['aadsso_access_token'] ?? '';

            return \is_string($token) ? $token : '';
        }

        return '';
    }

    /**
     * Get token expiration timestamp from session.
     *
     * @return int Unix timestamp when token expires, 0 if not available
     */
    private static function get_token_expires_at(): int
    {
        if (\PHP_SESSION_ACTIVE === session_status()) {
            $expires_at = $_SESSION['aadsso_token_expires_at'] ?? 0;

            return \is_int($expires_at) ? $expires_at : 0;
        }

        return 0;
    }

    /**
     * Get refresh token from session.
     *
     * @return string The refresh token or empty string if not available
     */
    private static function get_refresh_token(): string
    {
        if (\PHP_SESSION_ACTIVE === session_status()) {
            $refresh_token = $_SESSION['aadsso_refresh_token'] ?? '';

            return \is_string($refresh_token) ? $refresh_token : '';
        }

        return '';
    }

    /**
     * Convert a Microsoft Graph User model to a plain object.
     *
     * This ensures backward compatibility with existing code that expects
     * stdClass properties like $user->id, $user->mail, etc.
     *
     * @param Microsoft\Graph\Models\User $user The Graph SDK User model
     *
     * @return object Plain object representation
     */
    private static function user_to_object(Microsoft\Graph\Models\User $user): object
    {
        $data = [];

        if (null !== $user->getId()) {
            $data['id'] = $user->getId();
        }
        if (null !== $user->getDisplayName()) {
            $data['displayName'] = $user->getDisplayName();
        }
        if (null !== $user->getMail()) {
            $data['mail'] = $user->getMail();
        }
        if (null !== $user->getUserPrincipalName()) {
            $data['userPrincipalName'] = $user->getUserPrincipalName();
        }
        if (null !== $user->getGivenName()) {
            $data['givenName'] = $user->getGivenName();
        }
        if (null !== $user->getSurname()) {
            $data['surname'] = $user->getSurname();
        }
        if (null !== $user->getJobTitle()) {
            $data['jobTitle'] = $user->getJobTitle();
        }
        if (null !== $user->getDepartment()) {
            $data['department'] = $user->getDepartment();
        }
        if (null !== $user->getAccountEnabled()) {
            $data['accountEnabled'] = $user->getAccountEnabled();
        }

        // Handle additional properties via toArray()
        $additional_data = $user->toArray();
        if (\is_array($additional_data)) {
            $data = array_merge($additional_data, $data);
        }

        return (object) $data;
    }
}
