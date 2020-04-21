<?php /** @noinspection PhpInconsistentReturnPointsInspection */

namespace Gupalo\GoogleAuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class GoogleController extends AbstractController
{
    /**
     * Link to this controller to start the "connect" process
     *
     * @param Request $request
     * @return Response
     */
    public function login(Request $request): Response
    {
        $link = $this->get('oauth2.registry')->getClient('google')->getOAuth2Provider()->getAuthorizationUrl(['prompt' => 'consent']);

        if (!$request->cookies->get('logout')) {
            return RedirectResponse::create($link);
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
        // ** if you want to *authenticate* the user, then
        // leave this method blank and create a Guard authenticator
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
}
