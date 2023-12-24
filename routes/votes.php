<?php

    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Selective\BasePath\BasePathMiddleware;
    use Psr\Http\Message\ResponseInterface;
    use Slim\Exception\HttpNotFoundException;
    use Slim\Factory\AppFactory;
    use Selective\BasePath\BasePathDetector;
    use Slim\Middleware\BodyParsingMiddleware;

    $app = AppFactory::create();

    $app->add(new BasePathMiddleware($app));

    $app->addErrorMiddleware(true, true, true);
    $app->addBodyParsingMiddleware();