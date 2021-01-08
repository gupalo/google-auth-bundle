<?php /** @noinspection PhpInconsistentReturnPointsInspection */

namespace Gupalo\GoogleAuthBundle\Controller;

use Gupalo\GoogleAuthBundle\Security\GoogleAuthenticator;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class GoogleController extends AbstractController
{
    private GoogleAuthenticator $googleAuthenticator;

    public function __construct(GoogleAuthenticator $googleAuthenticator)
    {
        $this->googleAuthenticator = $googleAuthenticator;
    }

    /**
     * Link to this controller to start the "connect" process
     *
     * @param Request $request
     * @return Response
     */
    public function login(Request $request): Response
    {
        return $this->loginRegister($request, 'none');
    }

    /**
     * Link to this controller to start the "connect" process
     *
     * @param Request $request
     * @return Response
     */
    public function register(Request $request): Response
    {
        return $this->loginRegister($request, 'consent');
    }

    private function loginRegister(Request $request, string $prompt): Response
    {
        if ($this->googleAuthenticator->getCredentials($request) === 'dev') {
            return $this->redirectToTargetUrl($request);
        }

        $link = $this->get('oauth2.registry')->getClient('google')->getOAuth2Provider()->getAuthorizationUrl(['prompt' => $prompt]);

        if (!$request->cookies->get('logout')) {
            return new RedirectResponse($link);
        }

        $response = new Response();
        $response->headers->clearCookie('logout');

        return $this->render('@GoogleAuth/login.html.twig', [
            'link' => $link
        ], $response);
    }

    /**
     * After going to Google, you're redirect back here because this is the "redirect_route" you configured
     * in services.yaml
     *
     * @param Request $request
     * @return Response
     */
    public function check(Request $request): Response
    {
        return $this->redirectToTargetUrl($request);
    }

    public function logout(): Response
    {
        //
    }

    public function forceLogout(): RedirectResponse
    {
        $response = new RedirectResponse($this->get('router')->generate('google_auth_security_logout'));
        $response->headers->setCookie(new Cookie('logout', 1, '+1 hour'));

        return $response;
    }

    private function redirectToTargetUrl(Request $request): RedirectResponse
    {
        $url = null;
        try {
            $session = $request->getSession();
            $url = $session->get('_security.main.target_path') ;
        } catch (Throwable $e) {
        }
        if ($url === null) {
            $url = '/';
        }

        return $this->redirect($url);
    }
}
