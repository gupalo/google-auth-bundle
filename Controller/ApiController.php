<?php

namespace Gupalo\GoogleAuthBundle\Controller;

use Gupalo\GoogleAuthBundle\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;

class ApiController extends AbstractController
{
    /**
     * Provides key that can be used to connect to other services with GoogleAuthBundle
     *
     * @return JsonResponse {api_key: string}
     */
    public function key(): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        if (!$user) {
            return JsonResponse::create([
                'error' => 'not_authorized',
            ]);
        }

        return JsonResponse::create([
            'api_key' => $user->getApiKey(),
        ]);
    }
}
