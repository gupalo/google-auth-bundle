<?php

namespace Gupalo\GoogleAuthBundle\Controller;

use Gupalo\BrowserNotifier\BrowserNotifier;
use Doctrine\ORM\EntityManagerInterface;
use Gupalo\GoogleAuthBundle\Form\UserType;
use Gupalo\GoogleAuthBundle\Repository\UserRepository;
use Gupalo\UidGenerator\UidGenerator;
use InvalidArgumentException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Throwable;

class UserController extends AbstractController
{
    private BrowserNotifier $browserNotifier;

    public function __construct(BrowserNotifier $browserNotifier)
    {
        $this->browserNotifier = $browserNotifier;
    }

    /**
     * @Route("/admin/users", name="admin_user_index")
     * @param UserRepository $userRepository
     * @return Response
     */
    public function index(
        UserRepository $userRepository
    ): Response {
        $items = $userRepository->findBy([], ['username' => 'ASC']);

        return $this->render('@GoogleAuth/user/index.html.twig', [
            'items' => $items,
        ]);
    }

    /**
     * @Route("/admin/users/{username}", name="admin_user_edit")
     * @param string $username
     * @param Request $request
     * @param UserRepository $repository
     * @param EntityManagerInterface $entityManager
     * @return Response
     */
    public function edit(
        string $username,
        Request $request,
        UserRepository $repository,
        EntityManagerInterface $entityManager
    ): Response {
        $user = $repository->findOneByUsername($username);
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
            $entityManager->persist($user);
            try {
                $entityManager->flush();
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

    /**
     * @Route("/admin/users/{id}/enableDisable", name="admin_user_enable_disable")
     * @param int $id
     * @param Request $request
     * @param EntityManagerInterface $entityManager
     * @param UserRepository $userRepository
     * @return JsonResponse
     */
    public function enableDisable(
        int $id,
        Request $request,
        EntityManagerInterface $entityManager,
        UserRepository $userRepository
    ): JsonResponse {
        try {
            $user = $userRepository->find($id);
            if (!$user) {
                throw new InvalidArgumentException('user_not_found');
            }

            $user->setEnabled($request->request->get('enabled'));

            $entityManager->flush();

            $data = ['status' => 'ok', 'message' => '', 'enabled' => $user->getEnabled() ? 1 : 0];
        } catch (Throwable $e) {
            $data = ['status' => 'error', 'message' => $e->getMessage()];
        }

        return $this->json($data);
    }
}
