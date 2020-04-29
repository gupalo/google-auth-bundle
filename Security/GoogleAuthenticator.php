<?php

namespace Gupalo\GoogleAuthBundle\Security;

use DateTime;
use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use KnpU\OAuth2ClientBundle\Exception\MissingAuthorizationCodeException;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Security\Helper\FinishRegistrationBehavior;
use KnpU\OAuth2ClientBundle\Security\Helper\PreviousUrlHelper;
use KnpU\OAuth2ClientBundle\Security\Helper\SaveAuthFailureMessage;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Gupalo\GoogleAuthBundle\Entity\User;
use Gupalo\GoogleAuthBundle\Model\UserManager;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Throwable;

class GoogleAuthenticator extends SocialAuthenticator
{
    use PreviousUrlHelper;
    use SaveAuthFailureMessage;
    use FinishRegistrationBehavior;

    private const DEV_DOMAINS = [
        'user.dev' => [User::ROLE_USER],
        'manager.dev' => [User::ROLE_MANAGER],
        'admin.dev' => [User::ROLE_ADMIN],
        'user-admin.dev' => [User::ROLE_USER, User::ROLE_ADMIN],
    ];

    private const DEV_AVATARS = [
        User::ROLE_USER => 'data:image/gif;base64,R0lGODlhIAAgAKIAAOTj3z9FRniGiADR9vvNG7+9vf9hT////yH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoV2luZG93cykiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MzVCQzNENzk4OTk3MTFFQUJCODBDNjhGOTU1REQ2RjQiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6MzVCQzNEN0E4OTk3MTFFQUJCODBDNjhGOTU1REQ2RjQiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDozNUJDM0Q3Nzg5OTcxMUVBQkI4MEM2OEY5NTVERDZGNCIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDozNUJDM0Q3ODg5OTcxMUVBQkI4MEM2OEY5NTVERDZGNCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fTz8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15dXFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCsqKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAAAAAAALAAAAAAgACAAAAP/eLrcDAa4OQc1WNINhp3RJh7eARTFqS0AQYwTEMyB47acUwh0IKwLFwUALMwEgkGStgI2iCYFL+mpemYFmEnDs3o9vKzCqfNVA1b0NSCGDnsD2np51BoDAF5N/zvK2DAnNQcoWSmEAmKAIio8UlgKdwIKbCoxPjQme5MHgIM9g094hIN6RII+lBIyFI4NKXewDosTYUUBBGEPUyN3DHqQCz5iIjuDMigzeaFsxG8zpLx/PBKZjHg0YnyR2aEbe6PczkYp3hR4Tm4PyzDNnCN57xtGnc4xMmQTw7SX8tfJWciw0zLGx6pgpMIRNDElERFjqQieOrUDmI8fW04t3OggAQEAOw==',
        User::ROLE_MANAGER => 'data:image/gif;base64,R0lGODlhIAAgAKIAAOnp5YeHh0lGRQDPxP/CSLXDwP9mAP///yH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoV2luZG93cykiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NUUyNDhBNjk4OTk3MTFFQTk5NjdGNzhDMzBDNzgyRDgiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6NUUyNDhBNkE4OTk3MTFFQTk5NjdGNzhDMzBDNzgyRDgiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo1RTI0OEE2Nzg5OTcxMUVBOTk2N0Y3OEMzMEM3ODJEOCIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo1RTI0OEE2ODg5OTcxMUVBOTk2N0Y3OEMzMEM3ODJEOCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fTz8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15dXFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCsqKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAAAAAAALAAAAAAgACAAAAPpeLrc0DBKBgh5M58yCrNE02nMAJhUw43kMbxNgCkn2h4AhgkeNd8LwSPgIQInhQem0AMCkgzZgYf7QTO5n3BaDPiOtDAOHHkGzmfmzyloo99tgZctKwTibm9Bzpa//3d8NwBCgXiGcgJsFQYEBgZLQnZyaxKEB445Bgw9d3dNE5c5VzhQAJ93lQ6KB4FehG1DeXOhioRPinutXmeEZxqXU244iV17ulisrU2nHqdte7SWyrtoTajU0wvRZ200hqqrC7BxtJ6D1HvD39LAPK8KTDHZGnF2ZedOiHD2ZDRMRNKEa5HDkpIJCQAAOw==',
        User::ROLE_ADMIN => 'data:image/gif;base64,R0lGODlhIAAgAKIAANbSzUNDQ52bmwDA///PAP9hLgAAAP///yH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoV2luZG93cykiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6MTg1N0NCNjY4OTk3MTFFQUEzNDBDMkI1RjBDRkFGMzgiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6MTg1N0NCNjc4OTk3MTFFQUEzNDBDMkI1RjBDRkFGMzgiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDoxODU3Q0I2NDg5OTcxMUVBQTM0MEMyQjVGMENGQUYzOCIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDoxODU3Q0I2NTg5OTcxMUVBQTM0MEMyQjVGMENGQUYzOCIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fTz8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15dXFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCsqKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAAAAAAALAAAAAAgACAAAAP/eLrMQAS0SRUoZcJ5ZbVF1wDecmEfGEqAUB5CYIbpkh2AoXuBLtef3qEXM5AMAqCJgRQ4DQEnIPADkjwCI7XVcmUZrgppEc15nVKk6SWGor3dWFUJg0KpeKqdXaNm83lPSXQ5U3d+b0+EPYwxjmhRRHwMPTpygJh6PhVyh5mfUSmIoHhOVEABL2M4OKpzE6aDQ1sWRAuPFHhGCl9fQ0lqOHavOQqhwlM/W7swyrLCxrJ/lMHNyA1/uyVxYRbCthxTAgPkvEjg5APik2Qk5cJPHuQtr7lJrqkO1n3Sx7z+MVANykHrG7OA/IzJOBbw1L4UWVqocXgqiyAlfwbeOeiHBk6FMnQSAAA7',
        'default' => 'data:image/gif;base64,R0lGODlhIAAgAKIAAN3c3SlFPADJGI+JiQC8qv/FagDS/////yH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDM2LCAyMDE5LzA4LzEzLTAxOjA2OjU3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoV2luZG93cykiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6Qzg1OEIzODQ4OTk3MTFFQThDOEY4OERBQTRBRjc0NEYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6Qzg1OEIzODU4OTk3MTFFQThDOEY4OERBQTRBRjc0NEYiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpDODU4QjM4Mjg5OTcxMUVBOEM4Rjg4REFBNEFGNzQ0RiIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpDODU4QjM4Mzg5OTcxMUVBOEM4Rjg4REFBNEFGNzQ0RiIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PgH//v38+/r5+Pf29fTz8vHw7+7t7Ovq6ejn5uXk4+Lh4N/e3dzb2tnY19bV1NPS0dDPzs3My8rJyMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK+urayrqqmop6alpKOioaCfnp2cm5qZmJeWlZSTkpGQj46NjIuKiYiHhoWEg4KBgH9+fXx7enl4d3Z1dHNycXBvbm1sa2ppaGdmZWRjYmFgX15dXFtaWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQUA/Pj08Ozo5ODc2NTQzMjEwLy4tLCsqKSgnJiUkIyIhIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEAACH5BAAAAAAALAAAAAAgACAAAAPheLoL/KoUSJm59cjiMjSAwXSLpACkhx0OEAzUEASpp8hzntIDbDM4gWDW6b1egxqLMwoIn6+DDDeT1QrRxuwpDEiTR3ANwFQcnVDaIcf2ZajcrpvnfqOhaV/4F4x3qyw9Pzc5Q35DShRjd3EzgyMAfX86kIkLVIVDTpQnKB45BKGgokQjNqOkoQQBq3U2mJhVbJYPLo9SXj8uni0svr0yj7FsxKXCNCjJyihqt4IdLdC2tyxeSF67L9O3ti5JhDCC1Gu0X+PkJz2RRa6D4pGAZuUV4orNj8nFxDDR1Eq9HhIAADs=',
    ];

    private static bool $rememberMe = false;

    private ClientRegistry $clientRegistry;

    private RouterInterface $router;

    /** @var string[] */
    private $googleDomains;

    /** @var string[] */
    private array $allowedUsers;

    private ?UserManager $userManager;

    /** @var string[] */
    private array $adminUsers;

    /** @var string[] */
    private array $allowedUsernames;

    /** @var string[] */
    private array $adminUsernames;

    private ?string $defaultApiKey;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        UserManager $userManager = null,
        string $googleDomain = null,
        string $allowedUsernames = null,
        string $adminUsernames = null,
        string $defaultApiKey = null
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->userManager = $userManager;
        $this->googleDomains = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($googleDomain)))));
        $this->allowedUsernames = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($allowedUsernames)))));
        $this->adminUsernames = array_values(array_filter(array_map('trim', explode(',', mb_strtolower($adminUsernames)))));
        $this->defaultApiKey = $defaultApiKey;
    }

    /**
     * @param Request $request
     * @return AccessToken|string|null And can exit with redirect
     * @throws IdentityProviderException
     */
    public function getCredentials(Request $request)
    {
        if ($this->getDevRoles()) {
            return 'dev';
        }

        $token = $this->getApiKeyFromRequest($request);

        if (!$token) {
            try {
                $client = $this->getGoogleClient();
                $token = $client->getAccessToken();
            } catch (MissingAuthorizationCodeException $e) {
                header('Location: ' . $this->router->generate('google_auth_security_register'));
                exit;
            } catch (IdentityProviderException $e) {
                // you could parse the response to see the problem
                throw $e;
            }
        }

        return $token;
    }

    /**
     * @param AccessToken|string|null $credentials
     * @param UserProviderInterface $userProvider
     * @return User|null
     * @throws Exception
     */
    public function getUser($credentials, UserProviderInterface $userProvider): ?User
    {
        if ($credentials === null) {
            return null;
        }

        if ($this->getDevRoles()) {
            return $this->getDevUser();
        }

        // try login via api key
        if (is_string($credentials)) {
            if ($credentials === 'cli') {
                return $this->getCliUser();
            }

            $user = $this->userManager->findOneByApiKey($credentials);
            if ($user instanceof User) {
                $user->setIsApiAuth(true);
            }

            return $user;
        }

        $googleClient = $this->getGoogleClient();
        $googleUser = $googleClient->fetchUserFromToken($credentials);

        // 1) have they logged in with Google before? Easy!
        $existingUser = $this->userManager->findOneByGoogleId($googleUser->getId());
        if ($existingUser) {
            return $existingUser;
        }

        // 2) do we have a matching user by email?
        $email = $googleUser->getEmail();
        $user = $this->userManager->findOneByEmail($email);

        // 3) no user? Redirect to finish registration
        if (!$user) {
            $username = preg_replace('#@.*#', '', $email);
            $domain = mb_strtolower(preg_replace('#^.*@#', '', $email));

            if (!empty($this->googleDomains) && !in_array($domain, $this->googleDomains, true)) {
                throw new AuthenticationException();
            }

            $user = $this->createUser($email, $username);
        }

        if ($user && $googleUser) {
            $user
                ->setName($googleUser->getName())
                ->setFirstName($googleUser->getFirstName())
                ->setSurname($googleUser->getLastName())
                ->setPictureUrl($googleUser->getAvatar())
                ->setLocale($googleUser->getLocale())
                ->setIsEmailVerified($googleUser->toArray()['email_verified'] ?? false);
        }

        // make sure the Google user is set
        $user->setGoogleId($googleUser->getId());
        $user->setLastActiveAt(new DateTime());
        if (!$user->getRoles()) {
            $user->setRoles([User::ROLE_USER]);
        }
        if (!$user->getData()) {
            $user->setData([]);
        }
        $this->userManager->saveUser($user);

        if ($this->defaultApiKey && !$this->userManager->findOneByUsername('api')) {
            $this->saveApiUser();
        }

        $user->setIsApiAuth(false);

        return $user;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($this->getApiKeyFromRequest($request)) {
            return new JsonResponse(['message' => strtr($exception->getMessageKey(), $exception->getMessageData())], Response::HTTP_FORBIDDEN);
        }

        $this->saveAuthenticationErrorToSession($request, $exception);
        $loginUrl = $this->router->generate('google_auth_security_logout');

        return new RedirectResponse($loginUrl);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if ($this->getApiKeyFromRequest($request) || $this->getDevRoles()) {
            return null;
        }

        $url = $this->getPreviousUrl($request, $providerKey);
        if (!$url) {
            try {
                /** @noinspection PhpRouteMissingInspection */
                $url = $this->router->generate('homepage');
            } catch (Throwable $e) {
                $url = '/';
            }
        }

        return new RedirectResponse($url);
    }

    /**
     * Called when an anonymous user tries to access an protected page.
     *
     * In our app, this is never actually called, because there is only *one* "entry_point" per firewall and in security.yml,
     * we're using app.form_login_authenticator as the entry point (so it's start() method is the one that's called).
     * @param Request $request
     * @param AuthenticationException $authException
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        // not called in our app, but if it were, redirecting to the login page makes sense
        $url = $this->router->generate('google_auth_security_login');

        return new RedirectResponse($url);
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request): bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE or has api key
        return (
            $this->getDevRoles() ||
            $request->attributes->get('_route') === 'google_auth_connect_google_check' ||
            $this->getApiKeyFromRequest($request)
        );
    }

    public function supportsRememberMe(): bool
    {
        return self::$rememberMe && !$this->getDevRoles();
    }

    private function getGoogleClient(): OAuth2ClientInterface
    {
        return $this->clientRegistry->getClient('google');
    }

    private function isAllowedUsername(?string $username): bool
    {
        return (
            in_array($username, $this->allowedUsernames, true) ||
            $this->isAdminUsername($username)
        );
    }

    private function isAdminUsername(?string $username): bool
    {
        return in_array($username, $this->adminUsernames, true);
    }

    private function generateApiKey(): string
    {
        try {
            $apiKey = bin2hex(random_bytes(16));
        } catch (Throwable $e) {
            $apiKey = '';
        }

        return $apiKey;
    }

    private function getApiKeyFromRequest(Request $request): ?string
    {
        $apiKey = $request->headers->get('X-Api-Key');
        if (!$apiKey) {
            $apiKey = $request->request->get('apikey');
        }
        if (!$apiKey) {
            $apiKey = $request->query->get('apikey');
        }

        if (!$apiKey && $this->isCli()) {
            return 'cli';
        }

        self::$rememberMe = ($apiKey === null);

        if (!$apiKey) {
            $apiKey = null;
        }

        return $apiKey;
    }

    private function isCli(): bool
    {
        return (strpos(PHP_SAPI, 'cli') === 0 && strpos($_SERVER['argv'][0] ?? '', 'phpunit') === false);
    }

    private function getDevRoles(): array
    {
        $domain = $this->googleDomains[0] ?? '';

        return self::DEV_DOMAINS[$domain] ?? [];
    }

    private function getDevUser(): User
    {
        $domain = $this->googleDomains[0] ?: 'example.com';
        $username = preg_replace('#^role_#', '', strtolower($this->getDevRoles()[0] ?: 'dev'));
        $firstName = ucfirst($username);
        $surname = 'Dev';
        $email = sprintf('%s@%s', $username, $domain);

        $result = $this->userManager->findOneByEmail($email);

        if (!$result) {
            $this->userManager->saveUser(
                $this->userManager->createUser()
                    ->setEnabled(true)
                    ->setRoles($this->getDevRoles())
                    ->setUsername($username)
                    ->setEmail($email)
                    ->setApiKey($this->defaultApiKey)
                    ->setName(sprintf('%s %s', $firstName, $surname))
                    ->setFirstName($firstName)
                    ->setSurname($surname)
                    ->setPictureUrl(self::DEV_AVATARS[$this->getDevRoles()[0] ?? 'default'])
                    ->setIsEmailVerified(true)
                    ->setLocale('en-us')
                    ->setIsApiAuth(false)
                    ->setData([])
            );

            $result = $this->userManager->findOneByEmail($email);
        }

        return $result;
    }

    private function getCliUser(): User
    {
        return (new User(1))
            ->setEnabled(true)
            ->setRoles([User::ROLE_USER, User::ROLE_ADMIN])
            ->setUsername('cli');
    }

    private function saveApiUser(): void
    {
        $this->userManager->saveUser(
            $this->userManager->createUser()
                ->setEnabled(true)
                ->setEmail('api@example.com')
                ->setUsername('api')
                ->setRoles([User::ROLE_API])
                ->setApiKey($this->defaultApiKey)
                ->setData([])
        );
    }

    private function createUser($email, $username): User
    {
        $user = $this->userManager->createUser()
            ->setEnabled(false)
            ->setEmail($email)
            ->setUsername($username)
            ->setRoles([User::ROLE_USER])
            ->setData([]);

        if ($this->isAllowedUsername($username)) {
            $user->setEnabled(true);
            $user->setApiKey($this->generateApiKey());
        }

        if ($this->isAdminUsername($username)) {
            $user->setRoles([User::ROLE_USER, User::ROLE_ADMIN]);
        }

        return $user;
    }
}
