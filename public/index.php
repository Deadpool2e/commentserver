<?php
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Selective\BasePath\BasePathMiddleware;
    use Psr\Http\Message\ResponseInterface;
    use Slim\Exception\HttpNotFoundException;
    use Slim\Factory\AppFactory;
    use Selective\BasePath\BasePathDetector;

    require_once __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/../config/db.php';
    

    $app = AppFactory::create();



    // Add Slim routing middleware
    $app->addRoutingMiddleware();


    $app->add(new BasePathMiddleware($app));

    $app->addErrorMiddleware(true, true, true);



    require __DIR__ . '/../routes/route.php';
    // require __DIR__ . '/../routes/votes.php';

    $app->run();
