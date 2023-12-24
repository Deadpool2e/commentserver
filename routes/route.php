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
    

    $app->get('/', function (Request $request, Response $response) {
        $response->getBody()->write("Hello, world!");
        return $response;
    });


    $app->get('/hello/{name}', function (Request $request, Response $response, array $args) {
        $name = $args['name'];
        $response->getBody()->write("Hello, $name");
        return $response;
    });

    $app->get('/api/users', function (Request $request, Response $response) {
        $sql = "SELECT * FROM  user_data";
    
        try {
    
            $db = new db();
            $pdo = $db->connect();
    
            $stmt = $pdo->query($sql);
            $users = $stmt->fetchAll(PDO::FETCH_OBJ);
    
            $pdo = null;
            $response->getBody()->write(json_encode($users));
            return $response;
        } catch (\PDOException $e) {
            echo '{"msg": {"resp": ' . $e->getMessage() . '}}';
        }
    });
    
    $app->post('/api/register', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        
        $name = trim($parsedBody['name']) ;
        $email = trim($parsedBody['email']);
        $password = trim($parsedBody['password']);
        // $hashedPassword = password_hash($password,PASSWORD_DEFAULT);
    
        try {
            //get db object
            $db = new db();
            //connect
            $pdo = $db->connect();
    
            $sql = "INSERT INTO user_data (name,email,password) VALUES (?,?,?)";
    
            $pdo->prepare($sql)->execute([$name, $email, $password]);
    
            $response->getBody()->write('{"notice": {"text": "User '. $name .' has been just register."}}');
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(201); // 201 Created
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });


    $app->post('/api/login', function (Request $request, Response $response)  {
        $parsedBody = $request->getParsedBody();
        
        $email = trim($parsedBody['email']);
        $password = trim($parsedBody['password']);
        try {
            //get db object
            $db = new db();
            //connect
            $pdo = $db->connect();
    
            $sql = "SELECT * FROM user_data WHERE email = ?";
            
            // Use prepare and execute separately
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$email]);
    
            // Fetch the user data
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            // var_dump($user);`

            

            // Check if the user exists and the password is correct
            if ($user && ($password== $user['password'])) {
                // Respond with success message or user data
                $sessionToken = bin2hex(random_bytes(32));

                // Store the session token in the database
                $sqlUpdateSessionToken = "UPDATE user_data SET session_token = ? WHERE sno = ?";
                $stmtUpdateSessionToken = $pdo->prepare($sqlUpdateSessionToken);
                $stmtUpdateSessionToken->execute([$sessionToken, $user['sno']]);

                // Set a cookie with the session token
                setcookie('session_token', $sessionToken, time() + 3600, '/', '', false, true);
                $pdo = null;
                
                $response->getBody()->write(json_encode($user));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
            } else {

                // Respond with error message
                
                $response->getBody()->write('{"error": {"text": "Invalid credentials"}}');
                return $response->withHeader('Content-Type', 'application/json')->withStatus(401); // 401 Unauthorized
            }
        } catch (\PDOException $e) {
            // Respond with error message
            $response->getBody()->write('{"error": {"text": ' . json_encode($e->getMessage()) . '}}');
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });


    $app->get('/api/logout', function (Request $request, Response $response) {
        try {
            // Check if the user is authenticated (you may use middleware for this)
            // Retrieve the session token from the cookie
            $sessionToken = $_COOKIE['session_token'];
    
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Remove the session token from the database
            $sqlRemoveSessionToken = "UPDATE user_data SET session_token = NULL WHERE session_token = ?";
            $stmtRemoveSessionToken = $pdo->prepare($sqlRemoveSessionToken);
            $stmtRemoveSessionToken->execute([$sessionToken]);
    
            // Expire the cookie to log the user out
            setcookie('session_token', '', time() - 3600, '/', '', false, true);
    
            // Respond with success message or redirect to login page
            $response->getBody()->write('{"message": "Logout successful"}');
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\Exception $e) {
            // Respond with error message
            $response->getBody()->write('{"error": {"text": ' . json_encode($e->getMessage()) . '}}');
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });
    

    $app->get('/api/getAllPosts', function (Request $request, Response $response, array $args) {
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select all posts from the 'posts' table
            $sql = "SELECT * FROM posts";
            $stmt = $pdo->query($sql);
    
            // Fetch all posts as an associative array
            $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            // Convert the posts array to JSON and send it as a response
            $response->getBody()->write(json_encode($posts));
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->get('/api/getPost/{postId}', function (Request $request, Response $response, array $args) {
        $postId = $args['postId'];

        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();

            // Select a specific post from the 'posts' table
            $sql = "SELECT * FROM posts WHERE id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$postId]);

            // Fetch the post as an associative array
            $post = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$post) {
                // If the post with the specified ID doesn't exist, return a 404 response
                return $response->withHeader('Content-Type', 'application/json')->withStatus(404); // 404 Not Found
            }

            // Convert the post array to JSON and send it as a response
            $response->getBody()->write(json_encode($post));
            $pdo = null;

            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');

            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });


    
    $app->post('/api/addPost', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        
        $title = trim($parsedBody['title']) ;
        $content = trim($parsedBody['content']);
    
        try {
            //get db object
            $db = new db();
            //connect
            $pdo = $db->connect();
    
            $sql = "INSERT INTO posts (title,content) VALUES (?,?)";
    
            $pdo->prepare($sql)->execute([$title, $content]);
    
            $lastInsertId = $pdo->lastInsertId();

            $response->getBody()->write('{"id": ' . $lastInsertId . ', "message": "Post with ID ' . $lastInsertId . ' has been added."}');
            
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(201); // 201 Created
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });
    

    $app->post('/api/addComment', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        $userId = $parsedBody['user_id']; // Implement a function to get the logged-in user's ID
        $postId = $parsedBody['post_id'];
        $userName = $parsedBody['user_name'];
        $parentCommentId = $parsedBody['parent_comment_id'] ?? null; // for replies
        $content = $parsedBody['content'];
    
        try {
            // Check if the user is logged in
            if (!$userId) {
                return $response->withHeader('Content-Type', 'application/json')->withStatus(401); // 401 Unauthorized
            }

            $db = new db();
            //connect
            $pdo = $db->connect();
    
            // Insert the comment into the database
            $sql = "INSERT INTO comments (user_id, post_id, user_name, parent_comment_id, content) VALUES (?, ?, ?, ?, ?)";
            $pdo->prepare($sql)->execute([$userId, $postId, $userName, $parentCommentId, $content]);
    
            $response->getBody()->write('{"message": "Comment added successfully."}');
            return $response->withHeader('Content-Type', 'application/json')->withStatus(201); // 201 Created
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->get('/api/getComments/{postId}', function (Request $request, Response $response, array $args) {
        $postId = $args['postId'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select comments for the specified post from the 'comments' table
            $sql = "SELECT * FROM comments WHERE post_id = ? AND parent_comment_id IS NULL";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$postId]);
    
            // Fetch the comments as an associative array
            $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            // Fetch replies for each comment
            foreach ($comments as &$comment) {
                $comment['replies'] = fetchReplies($pdo, $comment['id']);
            }
    
            // Convert the comments array to JSON and send it as a response
            $response->getBody()->write(json_encode($comments));
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->get('/api/getComment/{id}', function (Request $request, Response $response, array $args) {
        $postId = $args['id'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select comments for the specified post from the 'comments' table
            $sql = "SELECT * FROM comments WHERE id = ? ";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$postId]);
    
            // Fetch the comments as an associative array
            $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            // Fetch replies for each comment
            foreach ($comments as &$comment) {
                $comment['replies'] = fetchReplies($pdo, $comment['id']);
            }
    
            // Convert the comments array to JSON and send it as a response
            $response->getBody()->write(json_encode($comments));
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->get('/api/getReplies/{id}', function (Request $request, Response $response, array $args) {
        $commentId = $args['id'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            $replies= fetchReplies($pdo,$commentId);
    
            // Convert the comments array to JSON and send it as a response
            $response->getBody()->write(json_encode($replies));
            $pdo = null;
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });
    
    function fetchReplies($pdo, $commentId) {
        $sql = "SELECT * FROM comments WHERE parent_comment_id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$commentId]);
    
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    $app->get('/api/getname/{userId}', function (Request $request, Response $response, array $args) {
        $userId = $args['userId'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select the name from the 'users' table based on the user_id
            $sql = "SELECT name FROM user_data WHERE sno = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$userId]);
    
            // Fetch the name as an associative array
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);
    
            if ($userData) {
                // Convert the name to JSON and send it as a response
                $response->getBody()->write(json_encode(['name' => $userData['name']]));
                $pdo = null;
    
                return $response->withHeader('Content-Type', 'application/json')->withStatus(200); // 200 OK
            } else {
                // User not found
                $response->getBody()->write('{"error": {"text": "User not found."}}');
                return $response->withHeader('Content-Type', 'application/json')->withStatus(404); // 404 Not Found
            }
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->put('/api/deleteComment', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        $userId = $parsedBody['user_id']; 
        $commentId = $parsedBody['comment_id'];
        $is_moderator = $parsedBody['is_moderator'];

        // Get user ID from your authentication system
         // Implement your own logic to get user ID
    
        // Check if the user has the right to delete the comment
        if (userCanDeleteComment($commentId, $userId)) {
            try {
                // Assuming you have a database connection available
                $db =new db(); // Implement your own function to get a database connection
                $pdo = $db->connect();
                // Delete the comment from the database
                $stmt = $pdo->prepare('DELETE FROM comments WHERE id = ?');
                $stmt->execute([$commentId]);
    
                
                // Return a success response
                $response->getBody()->write('{"Success": {"text": "Comment deleted."}}');
                return $response->withStatus(200);
            } catch (PDOException $e) {
                // Handle database errors
                $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
            }
        } else if($is_moderator){
            try {
                // Assuming you have a database connection available
                $db =new db(); // Implement your own function to get a database connection
                $pdo = $db->connect();
                // Delete the comment from the database
                $stmt = $pdo->prepare("UPDATE comments SET is_hidden = 1, content = 'This comment was deleted by a moderator.' WHERE id = ?");
                $stmt->execute([$commentId]);
    
                
                // Return a success response
                $response->getBody()->write('{"Success": {"text": "Comment updated."}}');
                return $response->withStatus(201);
            } catch (PDOException $e) {
                // Handle database errors
                $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
            }
        } 
        else{
            // User does not have the right to delete the comment
            return $response->withStatus(401);
        }
    });

    $app->put('/api/deleteupdateComment', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        $userId = $parsedBody['user_id']; 
        $commentId = $parsedBody['comment_id'];

        // Get user ID from your authentication system
         // Implement your own logic to get user ID
    
        // Check if the user has the right to delete the comment
        if (userCanDeleteComment($commentId, $userId)) {
            try {
                // Assuming you have a database connection available
                $db =new db(); // Implement your own function to get a database connection
                $pdo = $db->connect();
                // Delete the comment from the database
                $stmt = $pdo->prepare("UPDATE comments SET is_hidden = 1, content = 'This comment was deleted.' WHERE id = ?");
                $stmt->execute([$commentId]);
    
                
                // Return a success response
                $response->getBody()->write('{"Success": {"text": "Comment updated."}}');
                return $response->withStatus(201);
            } catch (PDOException $e) {
                // Handle database errors
                $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
            }
        } 
        else{
            // User does not have the right to delete the comment
            return $response->withStatus(401);
        }
    });

    $app->put('api/hideComment/{id}', function (Request $request, Response $response, array $args) {
        $commentId = $args['id'];

            try {
                // Assuming you have a database connection available
                $db =new db(); // Implement your own function to get a database connection
                $pdo = $db->connect();
                // Delete the comment from the database
                $stmt = $pdo->prepare("UPDATE comments SET is_hidden = 1, content = 'This comment is hidden by the moderator.' WHERE id = ?");
                $stmt->execute([$commentId]);
    
                
                // Return a success response
                $response->getBody()->write('{"Success": {"text": "Comment hidden."}}');
                return $response->withStatus(201);
            } catch (PDOException $e) {
                // Handle database errors
                $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
            }
    });

    function userCanDeleteComment($commentId, $userId) {
        try {
            // Assuming you have a database connection available
            $db = new db(); // Implement your own function to get a database connection
            $pdo = $db->connect();
            // Check if the user is the author of the comment
            $stmt = $pdo->prepare('SELECT user_id FROM comments WHERE id = :commentId');
            $stmt->bindParam(':commentId', $commentId, PDO::PARAM_INT);
            $stmt->execute();
            $authorId = $stmt->fetchColumn();
    
            
            return ($userId == $authorId) ;
        } catch (PDOException $e) {
            // Handle database errors
            return false;
        }
    }
       
    $app->put('/api/updateComment', function (Request $request, Response $response, array $args) {
        $parsedBody = $request->getParsedBody();
        $userId = $parsedBody['user_id']; 
        $commentId = $parsedBody['comment_id'];
        $editedText = $parsedBody['edited_text'];
        $is_moderator = $parsedBody['is_moderator'];
    
        // Validate user's authorization to update the comment (you may customize this part)
        if (userCanUpdateComment($commentId, $userId, $is_moderator)) {
            try {
    
                // Assuming you have a database connection available
                $db = new db(); // Implement your own function to get a database connection
                $pdo = $db->connect();
    
                // Update the comment in the database
                $stmt = $pdo->prepare('UPDATE comments SET content = ? WHERE id = ?');
                $stmt->execute([$editedText, $commentId]);
    
                // Return a success response
                $response->getBody()->write('{"Success": {"text": "Comment updated."}}');
                return $response->withStatus(200);
            } catch (PDOException $e) {
                // Handle database errors
                $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
                return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
            }
        } else {
            // User does not have the right to update the comment
            return $response->withStatus(401);
        }
    });

    function userCanUpdateComment($commentId, $userId, $is_moderator)
    {
        try {
            // Assuming you have a database connection available
            $db = new db(); // Implement your own function to get a database connection
            $pdo = $db->connect();

            // Check if the comment with the given ID exists
            $stmt = $pdo->prepare('SELECT user_id FROM comments WHERE id = ?');
            $stmt->execute([$commentId]);

            $comment = $stmt->fetch(PDO::FETCH_ASSOC);

            // If the comment is not found, return false
            if (!$comment) {
                return false;
            }

            

            // Check if the user is the author or has the "isAuthor" role
            return ($comment['user_id'] == $userId || $is_moderator);
        } catch (PDOException $e) {
            // Handle database errors (log or throw an exception)
            // For simplicity, returning false in case of an error, but you may want to handle this differently
            return false;
        }
    }

    function userIsAdmin($userId) {
        // Implement your own logic to check if the user has admin privileges
        // For example, check a user_roles table or a role column in your users table
        // Return true if the user is an admin, false otherwise
    }
    
    $app->post('/api/reportComment', function ($request, $response) {
        $data = $request->getParsedBody();
        $commentId = $data['comment_id'];
        $userId = $data['user_id'];
    
        // Check if the user has already reported this comment
        if (!userReportedComment($commentId, $userId)) {
            $db =new db(); // Implement your own function to get a database connection
            $pdo = $db->connect();
            $stmt = $pdo->prepare('SELECT reports FROM comments WHERE id = ?');
            $stmt->execute([$commentId]);
            $reportsCount = $stmt->fetchColumn();

            // Check if adding a new report would exceed the limit (e.g., 5)
            if ($reportsCount < 4) {
                // Add a new report
                try {
                    // Assuming you have a database connection available
                    
                    // Delete the comment from the database
                    $stmt = $pdo->prepare('INSERT INTO `reports` (`comment_id`, `user_id`) VALUES (?,?);');
                    $stmt->execute([$commentId,$userId]);
        
                    $sql = "UPDATE comments SET reports = reports + 1 WHERE id = ?;";     
                    $pdo->prepare($sql)->execute([$commentId]);

                    $pdo = null;
                    
                    // Return a success response
                    $response->getBody()->write('{"Success": {"text": "Comment reported successfully."}}');
                    return $response->withStatus(200);
                } catch (PDOException $e) {
                    // Handle database errors
                    $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
        
                    return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
                }
            }
            else{

                try {
                    // Assuming you have a database connection available
                    $db =new db(); // Implement your own function to get a database connection
                    $pdo = $db->connect();
                    // Delete the comment from the database
        
                    $sql = "UPDATE comments SET is_spam = 1 WHERE id = ?;";     
                    $pdo->prepare($sql)->execute([$commentId]);

                    
                    // Return a success response
                    $response->getBody()->write('{"Success": {"text": "Comment reported successfully."}}');
                    return $response->withStatus(403);
                } catch (PDOException $e) {
                    // Handle database errors
                    $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
        
                    return $response->withHeader('Content-Type', 'application/json')->withStatus(500); 
                }
            }
        } else {
            // User has already reported this comment
            return $response->withStatus(401);
        }
    });

    function userReportedComment($commentId, $userId) {
        try {
            // Assuming you have a database connection available
            $db = new db(); // Implement your own function to get a database connection
            $pdo = $db->connect();
    
            // Check if the user has already reported this comment
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM reports WHERE comment_id = :commentId AND user_id = :userId');
            $stmt->bindParam(':commentId', $commentId, PDO::PARAM_INT);
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->execute();
            
            return $stmt->fetchColumn() > 0;
        } catch (PDOException $e) {
            // Handle database errors
            return false;
        }
    }
    


    //upvote downvote

    $app->post('/api/upvoteComment', function (Request $request, Response $response, $args)  {
        $parsedBody = $request->getParsedBody();
        $commentId = $parsedBody['comment_id'];
        $userId = $parsedBody['user_id'];
        $commentUserId = $parsedBody['comment_user_id'];
    
        
        

        $hasUpvoted = hasUpvoted($commentId, $userId);
        $hasDownvoted = hasDownvoted($commentId, $userId);
    
        if (!$hasUpvoted && !$hasDownvoted) {
            // Increment upvote count in the database
            incrementUpvoteCount($commentId, $commentUserId);
    
            // Add the user's upvote record to the database
            addUserUpvoteRecord($commentId, $userId);
        } elseif ($hasDownvoted) {
            // User has already downvoted, toggle to upvote
            incrementUpvoteCount($commentId, $commentUserId);
            decrementDownvoteCount($commentId);
    
            // Update the user's vote record in the database
            removeUserDownvoteRecord($commentId, $userId);
            addUserUpvoteRecord($commentId, $userId);
        } elseif ($hasUpvoted) {
            // User has already upvoted, toggle to remove upvote
            decrementUpvoteCount($commentId, $commentUserId);
    
            // Remove the user's upvote record from the database
            removeUserUpvoteRecord($commentId, $userId);
        }


            // Return a response indicating success
            return $response->withStatus(200);
       
    });
    
    $app->post('/api/downvoteComment', function (Request $request, Response $response, $args)  {
        $parsedBody = $request->getParsedBody();
        $commentId = $parsedBody['comment_id'];
        $userId = $parsedBody['user_id'];
    
        // Update the database to record the downvote
        // You should perform appropriate validation, error handling, and security checks
        
        
           

        $hasUpvoted = hasUpvoted($commentId, $userId);
        $hasDownvoted = hasDownvoted($commentId, $userId);
    
        if (!$hasDownvoted && !$hasUpvoted) {
            // Increment downvote count in the database
            incrementDownvoteCount($commentId);
    
            // Add the user's downvote record to the database
            addUserDownvoteRecord($commentId, $userId);
        } elseif ($hasUpvoted) {
            // User has already upvoted, toggle to downvote
            incrementDownvoteCount($commentId);
            decrementUpvoteCount($commentId);
    
            // Update the user's vote record in the database
            removeUserUpvoteRecord($commentId, $userId);
            addUserDownvoteRecord($commentId, $userId);
        } elseif ($hasDownvoted) {
            // User has already downvoted, toggle to remove downvote
            decrementDownvoteCount($commentId);
    
            // Remove the user's downvote record from the database
            removeUserDownvoteRecord($commentId, $userId);
        }
            // Return a response indicating success
        return $response->withStatus(200);
        
    });
    
    $app->get('/api/updatedUpvote/{id}', function (Request $request, Response $response, array $args) {
        $commentId = $args['id'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select the name from the 'users' table based on the user_id
            $sql = "SELECT upvotes FROM comments WHERE id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$commentId]);
            $data = $stmt->fetch(PDO::FETCH_ASSOC);

            $response->getBody()->write(json_encode($data));
    
            return $response->withStatus(200);
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    $app->get('/api/updatedDownvote/{id}', function (Request $request, Response $response, array $args) {
        $commentId = $args['id'];
    
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Select the name from the 'users' table based on the user_id
            $sql = "SELECT downvotes FROM comments WHERE id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$commentId]);
            $data = $stmt->fetch(PDO::FETCH_ASSOC);

            $response->getBody()->write(json_encode($data));
    
            return $response->withStatus(200);
        } catch (\PDOException $e) {
            $response->getBody()->write('{"error": {"text": ' . $e->getMessage() . '}}');
    
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500); // 500 Internal Server Error
        }
    });

    function hasUpvoted($commentId, $userId) {
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();

            $stmt = $pdo->prepare("SELECT COUNT(*) FROM upvotes WHERE comment_id = ? AND user_id = ?");
            $stmt->execute([$commentId, $userId]);

            $count = $stmt->fetchColumn();

            return $count > 0;
        } catch (e) {
            return e; 
        }
    }

    function hasDownvoted($commentId, $userId) {
        try {
            // get db object
            $db = new db();
            // connect
            $pdo = $db->connect();

            $stmt = $pdo->prepare("SELECT COUNT(*) FROM downvotes WHERE comment_id = ? AND user_id = ?");
            $stmt->execute([$commentId, $userId]);

            $count = $stmt->fetchColumn();

            return $count > 0;
        } catch (e) {
            return e; 
        }
    }

    function addUserUpvoteRecord($commentId, $userId) {
    

        try {
            $db = new db();
                // connect
                $pdo = $db->connect();
            $stmt = $pdo->prepare("INSERT INTO upvotes (comment_id, user_id) VALUES (?, ?)");
            $stmt->execute([$commentId, $userId]);
        } catch (e) {
            return e; 
        }
    }
    
    function removeUserUpvoteRecord($commentId, $userId) {
        
    
        try {
            $db = new db();
                // connect
            $pdo = $db->connect();
            $stmt = $pdo->prepare("DELETE FROM upvotes WHERE comment_id = ? AND user_id = ?");
            $stmt->execute([$commentId, $userId]);
        } catch (e) {
            return e; 
        }
    }
    
    function addUserDownvoteRecord($commentId, $userId) {

    
        try {
            $db = new db();
                // connect
            $pdo = $db->connect();
            $stmt = $pdo->prepare("INSERT INTO downvotes (comment_id, user_id) VALUES (?, ?)");
            $stmt->execute([$commentId, $userId]);
        } catch (e) {
            return e; 
        }
    }
    
    function removeUserDownvoteRecord($commentId, $userId) {

    
        try {
            $db = new db();
                // connect
            $pdo = $db->connect();
            $stmt = $pdo->prepare("DELETE FROM downvotes WHERE comment_id = ? AND user_id = ?");
            $stmt->execute([$commentId, $userId]);
        } catch (e) {
            return e; 
        }
    }

    function incrementUpvoteCount($commentId, $userId) {
        try {
            $db = new db();
            // connect
            $pdo = $db->connect();
    
            // Update upvotes count in comments table
            $commentStmt = $pdo->prepare("UPDATE comments SET upvotes = upvotes + 1 WHERE id = ?");
            $commentStmt->execute([$commentId]);
    
            // Update upvotes count in user_data table
            $userStmt = $pdo->prepare("UPDATE user_data SET upvotes = upvotes + 1 WHERE sno = ?");
            $userStmt->execute([$userId]);
    
            // You can add additional logic here if needed
    
            return "Upvote count incremented successfully";
        } catch (Exception $e) {
            return $e->getMessage(); // Return the error message if an exception occurs
        }
    }
    

    function decrementUpvoteCount($commentId,$userId) {


        try {
            $db = new db();
                    // connect
            $pdo = $db->connect();
            $stmt = $pdo->prepare("UPDATE comments SET upvotes = upvotes - 1 WHERE id = ?");
            $stmt->execute([$commentId]);
            $userStmt = $pdo->prepare("UPDATE user_data SET upvotes = upvotes - 1 WHERE sno = ?");
            $userStmt->execute([$userId]);
        } catch (e) {
            return e; 
        }
    }

    function incrementDownvoteCount($commentId) {


        try {
            $db = new db();
                    // connect
                $pdo = $db->connect();
            $stmt = $pdo->prepare("UPDATE comments SET downvotes = downvotes + 1 WHERE id = ?");
            $stmt->execute([$commentId]);
        } catch (e) {
            return e; 
        }
    }

    function decrementDownvoteCount($commentId) {


        try {
            $db = new db();
                    // connect
                $pdo = $db->connect();
            $stmt = $pdo->prepare("UPDATE comments SET downvotes = downvotes - 1 WHERE id = ?");
            $stmt->execute([$commentId]);
        } catch (e) {
            return e; 
        }
    }



