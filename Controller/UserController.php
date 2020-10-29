<?php

namespace Gupalo\GoogleAuthBundle\Controller;

use Gupalo\BrowserNotifier\BrowserNotifier;
use Gupalo\GoogleAuthBundle\Form\UserType;
use Gupalo\GoogleAuthBundle\Model\UserManager;
use Gupalo\UidGenerator\UidGenerator;
use InvalidArgumentException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class UserController extends AbstractController
{
    private BrowserNotifier $browserNotifier;

    private UserManager $userManager;

    public function __construct(BrowserNotifier $browserNotifier, UserManager $userManager)
    {
        $this->browserNotifier = $browserNotifier;
        $this->userManager = $userManager;
    }

    public function index(): Response
    {
        return $this->render('@GoogleAuth/user/index.html.twig', [
            'items' => $this->userManager->findAll(),
        ]);
    }

    public function edit(string $username, Request $request): Response
    {
        $user = $this->userManager->findOneByUsername($username);
        if (!$user) {
            $this->browserNotifier->warning(sprintf('Cannot find User "%s"', $username));

            return $this->redirectToRoute('admin_user_index');
        }

        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            if (!$user->getApiKey()) {
                $user->setApiKey(UidGenerator::generate());
            }
            try {
                $this->userManager->saveUser($user);
                $this->browserNotifier->success(sprintf('Updated User "%s"', $user->getUsername()));

                return $this->redirectToRoute('admin_user_index');
            } catch (Throwable $e) {
                $this->browserNotifier->error($e->getMessage());
            }
        }

        return $this->render('@GoogleAuth/user/edit.html.twig', [
            'form' => $form->createView(),
        ]);
    }

    public function enableDisable(int $id, Request $request): JsonResponse
    {
        try {
            $user = $this->userManager->find($id);
            if (!$user) {
                throw new InvalidArgumentException('user_not_found');
            }

            $user->setEnabled($request->request->get('enabled'));
            $this->userManager->saveUser($user);

            $data = ['status' => 'ok', 'message' => '', 'enabled' => $user->getEnabled() ? 1 : 0];
        } catch (Throwable $e) {
            $data = ['status' => 'error', 'message' => $e->getMessage()];
        }

        return $this->json($data);
    }
}
