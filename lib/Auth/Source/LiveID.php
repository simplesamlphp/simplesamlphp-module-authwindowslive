<?php

namespace SimpleSAML\Module\authwindowslive\Auth\Source;

use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

/**
 * Authenticate using LiveID.
 *
 * @package SimpleSAMLphp
 */
class LiveID extends \SimpleSAML\Auth\Source
{
    /**
     * The string used to identify our states.
     */
    public const STAGE_INIT = 'authwindowslive:init';

    /**
     * The key of the AuthId field in the state.
     */
    public const AUTHID = 'authwindowslive:AuthId';

    /** @var string */
    private $key;

    /** @var string */
    private $secret;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     *
     * @throws \Exception In case of misconfiguration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!array_key_exists('key', $config)) {
            throw new Exception('LiveID authentication source is not properly configured: missing [key]');
        }

        $this->key = $config['key'];

        if (!array_key_exists('secret', $config)) {
            throw new Exception('LiveID authentication source is not properly configured: missing [secret]');
        }

        $this->secret = $config['secret'];
    }


    /**
     * Log-in using LiveID platform
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        // we are going to need the authId in order to retrieve this authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateID = Auth\State::saveState($state, self::STAGE_INIT);

        Logger::debug('authwindowslive auth state id = ' . $stateID);

        // authenticate the user
        // documentation at:
        // https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-oauth-code/
        $authorizeURL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize' .
            '?client_id=' . $this->key .
            '&response_type=code' .
            '&response_mode=query' .
            '&redirect_uri=' . urlencode(Module::getModuleURL('authwindowslive') . '/linkback.php') .
            '&state=' . urlencode($stateID) .
            '&scope=' . urlencode('openid https://graph.microsoft.com/user.read')
        ;

        Utils\HTTP::redirectTrustedURL($authorizeURL);
    }

    /**
     * @param array &$state
     * @throws \Exception
     */
    public function finalStep(array &$state): void
    {
        Logger::debug(
            "authwindowslive oauth: Using this verification code [" . $state['authwindowslive:verification_code'] . "]"
        );

        // retrieve Access Token
        // documentation at:
        // https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-oauth-code/#request-an-access-token
        $postData = 'client_id=' . urlencode($this->key) .
            '&client_secret=' . urlencode($this->secret) .
            '&scope=' . urlencode('https://graph.microsoft.com/user.read') .
            '&grant_type=authorization_code' .
            '&redirect_uri=' . urlencode(Module::getModuleURL('authwindowslive') . '/linkback.php') .
            '&code=' . urlencode($state['authwindowslive:verification_code']);

        $context = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => $postData,
            ],
        ];

        /** @var string $result */
        $result = Utils\HTTP::fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', $context, false);

        $response = json_decode($result, true);

        // error checking of $response to make sure we can proceed
        if (!array_key_exists('access_token', $response)) {
            throw new Exception(
                '[' . $response['error'] . '] ' . $response['error_description'] .
                "\r\nNo access_token returned - cannot proceed\r\n" . implode(', ', $response['error_codes'])
            );
        }

        Logger::debug(
            "authwindowslive: Got an access token from the OAuth service provider [" . $response['access_token'] . "]"
        );

        // documentation at: http://graph.microsoft.io/en-us/docs/overview/call_api
        $opts = [
            'http' => ['header' => "Accept: application/json\r\nAuthorization: Bearer " .
                $response['access_token'] . "\r\n"]
        ];

        /** @var string $data */
        $data = Utils\HTTP::fetch('https://graph.microsoft.com/v1.0/me', $opts);
        $userdata = json_decode($data, true);

        // this is the simplest case
        if (!array_key_exists('@odata.context', $userdata) || array_key_exists('error', $userdata)) {
            throw new Exception(
                'Unable to retrieve userdata from Microsoft Graph [' . $userdata['error']['code'] . '] ' .
                $userdata['error']['message']
            );
        }
        $attributes = [];
        $attributes['windowslive_targetedID'] = [
            'https://graph.microsoft.com!' . (!empty($userdata['id']) ? $userdata['id'] : 'unknown')
        ];
        foreach ($userdata as $key => $value) {
            if (is_string($value)) {
                $attributes['windowslive.' . $key] = [$value];
            }
        }


        Logger::debug('LiveID Returned Attributes: ' . implode(", ", array_keys($attributes)));

        $state['Attributes'] = $attributes;
    }
}
