document.addEventListener('DOMContentLoaded', initializePong);

function initializePong() {

/************************************************************************************************ */
/*                                   INITIALIZE SCRIPT VARIABLES                                  */
/************************************************************************************************ */


    let isGameRunning = false;
	let canvas, context;
    let canvasWidth, canvasHeight;
    let wPressed = false, sPressed = false, upPressed = false, downPressed = false;
    let socketGame;
    let socketRoom;
    let socketTournament;
    let roomName;
    let roomTournamentName;
    let tournamentIsRunning = false;
    let gameMode;
	let players_ready = false;
    let tournamentScores = [[0,0], [0,0], [0,0], [0,0], [0,0], [0,0], [0,0]];
    let tournamentPlayers = [];
    let tournamentRound2Players = [];
    let tournamentRound3Players = [];
    let tournamentNextRoundPlayers = [];
    let tournamentRound = 1;
    let tournamentMatch = 1;
    let tournamentWinner;
	let CSRFToken;

    const backgroundImage = new Image();
    backgroundImage.src = '/static/game/images/brakmar_terrain_correct.png';

    const ballImage = new Image();
    ballImage.src = '/static/game/images/boufbowl.png';

	CSRFToken = getCookie('csrftoken');

/************************************************************************************************ */
/*                                   LOAD CONTENT + UTILS                                         */
/************************************************************************************************ */

	function loadContent(url, targetElementId) {
		// Retourne une nouvelle promesse
		return new Promise((resolve, reject) => {
            data = {
                'Players': tournamentPlayers,
                'Round2Players': tournamentRound2Players,
                'Round3Players': tournamentRound3Players,
                'Winner': tournamentWinner,
                'Scores': tournamentScores
            }
			fetch(url, {
                method: 'POST',
				headers: {
					'Authorization': getCookie('access_token'),
					'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
				},
                cookies: {'csrftoken': getCookie('csrftoken')},
                body: JSON.stringify(data)
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
				const content = doc.querySelector('#content') ? doc.querySelector('#content').innerHTML : html;
	
				document.getElementById(targetElementId).innerHTML = content;
				// Résout la promesse avec le contenu
				resolve(content);
			})
			.catch(error => {
				console.log('Error load content:', error);
				// Rejette la promesse en cas d'erreur
				reject(error);
			});
		});
	}

    // Resize the canvas and redraw the game
    function resizeCanvas(roomName)
	{
        const gameContainer = document.getElementById('game');
		if (!gameContainer) {
			console.log('Game container not found');
			return;
		}
		canvas = document.getElementById('pongCanvas');
		context = canvas.getContext('2d');
        canvas.width = gameContainer.clientWidth;
        canvas.height = gameContainer.clientHeight;
        canvasWidth = canvas.width;
        canvasHeight = canvas.height;
        if (socketGame && roomName)
        {
            // console.log("Redraw the game");
            sendGameMessage({
                action: 'redraw',
                room: roomName,
                canvas_width: canvasWidth,
                canvas_height: canvasHeight
            });
        }
        else
        {
            console.error("WebSocket Game not initialized");
        }
    }


/************************************************************************************************ */
/*                                   LOCAL GAME MODE                                              */
/************************************************************************************************ */

    function launchLocalGame(player1, player2, game_mode)
    {
        roomName = Math.random().toString(36).substring(2, 6) + Math.random().toString(36).substring(2, 6);
        if (roomName)
        {
            decoded_token = jwt_decode(getCookie('access_token'));
            initializeRoomWebSocket()
            .then(() => {
                checkAndAddRoom(roomName)
                .then(() => {
                    // console.log("Start button clicked");
                    socketRoom.close();
                    if (isGameRunning == false) {
                        isGameRunning = true;
                        resizeCanvas();
                        initializeGameWebSocket(roomName).then(() => {
                            if (game_mode === 'local')
                            {
								gameMode = 'local';
                                const btn = document.getElementById('backHomeBtn3');
                                if (btn)
                                    btn.style.display = 'inline';
                                sendGameMessage({
                                    action: 'start',
                                    game_mode: game_mode,
                                    canvas_width: canvasWidth,
                                    canvas_height: canvasHeight,
                                    player1: player1,
                                    player2: player2
                                });
                            }
                            else if (game_mode === 'tournament')
                            {
								gameMode = 'tournament';
                                const btn = document.getElementById('backHomeBtn1');
                                if (btn)
                                    btn.style.display = 'inline';
                                sendGameMessage({
                                    action: 'initialize_tournament',
                                    game_mode: game_mode,
                                    canvas_width: canvasWidth,
                                    canvas_height: canvasHeight,
                                    player1: player1,
                                    player2: player2
                                })
                            }
                        }).catch(error => {
                            console.error("WebSocket Game connection failed: ", error);
                        });
                    }
                })
                .catch((error) => {
                    console.log('Room creation failed', error);
                });
            })
            .catch(error => {
                console.error("WebSocket Room connection failed: ", error);
            });
        }
    }

    document.getElementById('content').addEventListener('click', function (event) {
        const startBtn = event.target.closest('#startBtn');
        if (startBtn)
        {
            startBtn.style.display = 'none';
            if (window.location.pathname.includes('tournament'))
            {
                sendGameMessage({
                    action: 'start_tournament',
                    canvas_width: canvasWidth,
                    canvas_height: canvasHeight,
                    player1: player1,
                    player2: player2
                });
                console.log("Start tournament button clicked");
            }
            else
            {
                launchLocalGame('Player1', 'Player2', 'local');
            }
        }
    });

	document.getElementById('content').addEventListener('click', function (event) {
        const stopBtn = event.target.closest('#stopBtn');
        if (stopBtn)
        {
            // console.log("Stop button clicked");
            if (isGameRunning) {
                isGameRunning = false;
                sendGameMessage({
                    action: 'stop',
                    canvas_width: canvasWidth,
                    canvas_height: canvasHeight
                });
            }
        }
    });
/************************************************************************************************ */
/*                                   ONLINE GAME MODE                                             */
/************************************************************************************************ */


	function sendRoomSocketMessage(action, roomName) {
		return new Promise((resolve, reject) => {
			// Envoi du message à la WebSocket
			socketRoom.send(JSON.stringify({
				action: action,
				room_name: roomName,
			}));

			socketRoom.onmessage = function(event) {
				const data = JSON.parse(event.data);
				// Vérifie si le message reçu est la réponse attendue
				if (data.status === 'added')
				{
					resolve({ status: data.status });
				}
				else if (data.status === 'creation_failed')
				{
					reject({ status: data.status, room: data.room_name });
				}
				else if (data.status === 'found')
				{
					resolve({ status: data.status});
				}
				else if (data.status === 'not_found')
				{
					reject({ status: data.status, room: data.room_name });
				}
				else if (data.status === 'deleted')
				{
					resolve({ status: data.status });
				}
				else if (data.status === 'error')
				{
					reject({ status: data.status});
				}
			};

			socketRoom.onerror = function() {
				return { status: 'error'};
			};
		});
	}

	async function checkAndAddRoom(roomName) {
		const serverResponse = await sendRoomSocketMessage('add', roomName);

		return new Promise((resolve, reject) => {

			if (serverResponse.status === 'added')
			{
				resolve(serverResponse);
			}
			else
			{
				reject(new Error(`Room ${roomName} creation failed.`));
			}
		});
	}

	async function deleteRoom(roomName) {
		const serverResponse = await sendRoomSocketMessage('delete', roomName);

		return new Promise((resolve, reject) => {

			if (serverResponse.status === 'deleted')
			{
				resolve(serverResponse);
			}
			else
			{
				reject(new Error(`Room ${roomName} deletion failed.`));
			}
		});
	}

	async function checkRoom(roomName) {
		const serverResponse = await sendRoomSocketMessage('check', roomName); // Remplacer par votre logique de vérification
		return new Promise((resolve, reject) => {
			// Simuler une requête au serveur pour vérifier la salle
		
			if (serverResponse.status === 'found')
			{
				resolve(serverResponse);
			}
			else
			{
				reject(new Error(`Room ${roomName} not found.`));
			}
		});
	}


    // Create a new room
	// createRoomBtn = document.getElementById('createRoomBtn');
    document.getElementById('content').addEventListener('click', function (event) {
        const createRoomBtn = event.target.closest('#createRoomBtn');
        if (createRoomBtn)
        {
            // console.log("Create room button clicked");
            roomName = Math.random().toString(36).substring(2, 6) + Math.random().toString(36).substring(2, 6);
            if (roomName)
            {
				decoded_token = jwt_decode(getCookie('access_token'));
                initializeRoomWebSocket()
                .then(() => {
                    checkAndAddRoom(roomName)
                    .then(() => {
                        socketRoom.close();
                        loadContent("/game/online/" + roomName + "/", "content").then(content => {
                            const url = "/game/online/";
                            // history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/game/'

                            if (isGameRunning == false) {
                                resizeCanvas(roomName);
								gameMode = 'online';
                                initializeGameWebSocket(roomName)
                                .then(() =>
                                {
                                    sendGameMessage({
                                        action: 'initialize',
                                        room: roomName,
                                        game_mode: 'online',
                                        player_id: decoded_token.user_id,
                                        player_nick: decoded_token.nickname,
                                        canvas_width: canvasWidth,
                                        canvas_height: canvasHeight
                                    });
                                })
                                .catch(error =>
                                {
                                    console.error("WebSocket Game connection failed: ", error);
                                    isGameRunning = false;
                                });
                            }
                        });
                    })
                    .catch((error) => {
                        console.log('Room creation failed', error);
                    });
                })
                .catch(error => {
                    console.error("WebSocket Room connection failed: ", error);
                });
            }
            else
            {
                console.log('Room creation failed');
            }
        }
    });

    // Copy room code to clipboard
    document.getElementById('content').addEventListener('click', function (event) {
        const copyBtn = event.target.closest('#copyRoomCodeBtn');
        if (copyBtn) {
            const roomCode = copyBtn.getAttribute('data-room-code');
            navigator.clipboard.writeText(roomCode)
            .then(() => {
                console.log('Code de la room copié dans le presse-papiers');
                // alert('Room code copied to clipboard');
                // Afficher un message ou effectuer une action après la copie
            })
            .catch(err => {
                console.error('Erreur lors de la tentative de copie dans le presse-papiers : ', err);
            });
        }
    });

    function checkIfRoomFull(roomName) {
        return new Promise((resolve, reject) => {

			decoded_token = jwt_decode(getCookie('access_token'));

            sendGameMessage({
                action: 'check_full',
                room: roomName
            });

            // console.log('Checking if room is full');
            socketGame.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.status === 'full')
                {
                    console.log('Room is full');
                    reject();
                }
                else if (data.status === 'not_full')
                {
                    console.log('Room is not full');
                    resolve();
                }
            };
        });
    }

	function checkIdDouble(roomName) {
        return new Promise((resolve, reject) => {

            decoded_token = jwt_decode(getCookie('access_token'));
            sendGameMessage({
                action: 'check_id',
                room: roomName,
                player_id: decoded_token.user_id,
            });

            socketGame.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.status === 'double')
                {
                    console.log('User already in room');
                    reject();
                }
                else if (data.status === 'not_double')
                {
                    console.log('User not in room');
                    resolve();
                }
            };
        });
    }

    // Join a room by code
    document.getElementById('content').addEventListener('click', function (event) {
        const joinRoomBtn = event.target.closest('#joinRoomBtn');
        if (joinRoomBtn)
        {
            // console.log("Join room button clicked");
            roomName = document.getElementById('roomName').value;
            if (roomName)
            {
				decoded_token = jwt_decode(getCookie('access_token'));
				nick = decoded_token.nickname;
                initializeRoomWebSocket()
                .then(() => {
                    checkRoom(roomName)
                    .then(() => {
                        socketRoom.close();
                        initializeGameWebSocket(roomName)
                        .then(() =>
                        {
                            checkIfRoomFull(roomName)
                            .then(() => {
								checkIdDouble(roomName)
								.then(() => {
									loadContent("/game/online/" + roomName + "/", "content")
									.then(content => {
										const url = "/game/online/";
										// history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/game/'
											if (isGameRunning == false) {
												gameMode = 'online';
												initializeGameWebSocket(roomName)
												.then(() =>
												{
													resizeCanvas();
													sendGameMessage({
														action: 'initialize',
														room: roomName,
														player_nick: decoded_token.nickname, 
														player_id: decoded_token.user_id,
														canvas_width: canvasWidth,
														canvas_height: canvasHeight
													});
												})
												.catch(error =>
												{
													console.error("WebSocket Game connection failed: ", error);
													isGameRunning = false;
												});
											}
									});
								})
								.catch(() => {
									alert("User already in room");
									if (socketGame && socketGame.readyState === WebSocket.OPEN)
										socketGame.close();
								});
                            })
                            .catch(() => {
                                if (socketGame && socketGame.readyState === WebSocket.OPEN)
                                    socketGame.close();
                                alert('Room is full');
                            });
                        })
                        .catch(error =>
                        {
                            console.error("WebSocket Game connection failed: ", error);
                            isGameRunning = false;
                        });
                    })
                    .catch(() => {
                        alert('Room does not exist');
                    });
                })
                .catch(error => {
                    console.error("WebSocket Room connection failed: ", error);
                });
            }
            else
            {
                alert('Please enter a room name');
            }
        }
    });

    // Ready button
   	document.getElementById('content').addEventListener('click', function(event) {
		const readyBtn = event.target.closest('#readyBtn');
		if (readyBtn && players_ready == false) {
            decoded_token = jwt_decode(getCookie('access_token'));
			// console.log("Ready button clicked");
			readyBtn.style.display = 'None';
            const btn = document.getElementById('backHomeBtn2');
            if (btn)
                btn.style.display = 'inline';
			sendGameMessage({
				action: 'ready',
				player_name: decoded_token.nickname,
			});
		}
	});


    function startCountdown(seconds) {
        return new Promise((resolve, reject) => {
            let remaining = seconds;

            const countdownInterval = setInterval(() => {
				// console.log(remaining);
                // drawCountdown(remaining);
				sendGameMessage({
					action: 'countdown',
					seconds: remaining
				});
                remaining--;

                if (remaining < 0) {
                    clearInterval(countdownInterval);
                    resolve();
                }
                if (socketGame.readyState === WebSocket.CLOSED) {
                    clearInterval(countdownInterval);
                    reject();
                }
            }, 1000);
        });
    }

/************************************************************************************************ */
/*                                  ROOM WEB SOCKET MANAGEMENT                                    */
/************************************************************************************************ */

    function initializeRoomWebSocket() {
        socketRoom = new WebSocket('wss://' + window.location.hostname + ':8000/ws/rooms/');
        
        return new Promise((resolve, reject) => {
            socketRoom.onopen = () => {
                console.log('WebSocket Rooms connection opened');
                resolve();
            };

            socketRoom.onerror = (error) => {
                console.error('WebSocket Rooms error: ', error);
                reject(error);
            };

            socketRoom.onclose = () => {
                console.log('WebSocket Rooms connection closed');
                isGameRunning = false;
            };

            window.addEventListener('beforeunload', () => {
				closeGameSocketIfNotInGame(roomName)
				.then(() => {
					closeRoomSocketIfNotInGame();
				});
				resetTournament();
				players_ready = false;
				isGameRunning = false;
            });
        });
    }


    function closeRoomSocketIfNotInGame() {
        // Vérifier si l'URL contient 'game/online'
        if (socketRoom && socketRoom.readyState === WebSocket.OPEN) {
            // Fermer la socket
            console.log('Closing WebSocket Rooms connection');
            socketRoom.close();
        }
    }

    window.addEventListener('moveurl', function() {
		closeGameSocketIfNotInGame(roomName)
        .then(() => {
			closeRoomSocketIfNotInGame();
        });
		resetTournament();
		players_ready = false;
		isGameRunning = false;
    });


/************************************************************************************************ */
/*                                  GAME WEB SOCKET MANAGEMENT                                    */
/************************************************************************************************ */

    function initializeGameWebSocket(roomName) {
        socketGame = new WebSocket('wss://' + window.location.hostname + ':8000/ws/game/' + roomName + '/');

        return new Promise((resolve, reject) => {
            socketGame.onopen = () => {
                console.log('WebSocket Game connection opened');
                resolve();
            };
    
            socketGame.onerror = (error) => {
                console.error('WebSocket Game error: ', error);
                reject(error);
            };
    
            socketGame.onmessage = (event) => {3
                const data = JSON.parse(event.data);
    
                if (data.status === 'started') {
					console.log("Game started");
					players_ready = true;
                    draw(data.state);
					startCountdown(3)
                    .then(() => {
                        isGameRunning = true;
                    })
                    .then(() => {
                        gameLoop();
                    })
                    .catch((error) => {
                        console.error('Countdown failed :', error);
                    });
                }
                else if (data.status === 'initialized') {
                    draw(data.state);
                }
                else if (data.status === 'countdown') {
                    draw(data.state);
                }
                else if (data.status === 'updated') {
					if (data.state.end_game === 1)
						isGameRunning = false;
                    draw(data.state);
                }
                else if (data.status === 'stopped')
				{
					if (isGameRunning)
					{
						isGameRunning = false;
            			decoded_token = jwt_decode(getCookie('access_token'));
						if (data.state.player_left_id == decoded_token.user_id)
						{
							// console.log("Save score");
							// CSRFToken = getCookie('csrftoken');
							sendGameMessage({
								action: 'save_score',
                                disconnected: 'no',
								csrftoken: CSRFToken,
							});
						}
                        if (data.state.game_mode === 'local')
                        {
                            if (socketGame && socketGame.readyState === WebSocket.OPEN) {
                                socketGame.close();
                            }
                        }
                        else if (data.state.game_mode === 'tournament')
                        {
                            if (tournamentRound === 1)
                            {
                                tournamentRound2Players.push(data.state.winner);
                            }
                            else if (tournamentRound === 2)
                                tournamentRound3Players.push(data.state.winner);
                            else if (tournamentRound === 4)
                                tournamentWinner = data.state.winner;
                            tournamentScores[tournamentMatch - 2] = [data.state.score_left, data.state.score_right];
                            // console.log("tournamentScores :", tournamentScores);
                            displayCountdownTournament(3)
							.then(() => {
                            	displayTournamentPlayers();
							})
                        }
					}
					draw(data.state);
				}
                else if (data.status === 'redraw') {
                    draw(data.state);
                }
				// else if (data.status === 'disconnected') {	
				// 	if (isGameRunning)
				// 		console.log("Save score");
				// 		sendGameMessage({
				// 			action: 'save_score',
				// 			disconnected: 'yes',
				// 		});
				// 		draw(data.state);
				// 		isGameRunning = false;
				// }
                else if (data.status === 'close') {
                    players_ready = false;
                    isGameRunning = false;
					socketGame.close();
                }
				else if (data.status === 'closeRoom') {
                    players_ready = false;
                    isGameRunning = false;
					socketGame.close();
                    initializeRoomWebSocket()
                    .then(() => {
                        deleteRoom(data.room)
                        .then(() => {
                            console.log('Room ', data.room, ' deleted');
                            socketRoom.close();
                        })
                        .catch((error) => {
                            console.log('Room deletion failed', error);
                            socketRoom.close();
                        });
                    })
                    .catch(error => {
                        console.error("WebSocket Room connection failed: ", error);
                    });
                }
                else if (data.status === 'ready') {
                    draw(data.state);
                }
                else if (data.status === 'tournament_match_initialized')
                {
                    draw(data.state);
                }
                else if (data.status === 'debug') {
                    console.log("debug : ", data.message);
                }
            };
    
            socketGame.onclose = () => {
                console.log('WebSocket Game connection closed');
                isGameRunning = false;
            };
    
            window.addEventListener('beforeunload', () => {
                socketGame.close();
            });
        });
    }

    function sendGameMessage(message)
	{
        if (socketGame && socketGame.readyState === WebSocket.OPEN) {
            socketGame.send(JSON.stringify(message));
        } else {
            console.error("WebSocket Game is not open. Ready state: ", socketGame ? socketGame.readyState : 'no socket');
        }
    }

    function closeGameSocketIfNotInGame(roomName) {
        return new Promise((resolve) => {
            // Vérifier si la socket de la salle de jeu existe et est ouverte
            if (socketGame && socketGame.readyState === WebSocket.OPEN) {
                // Fermer la socket
                console.log('Closing WebSocket Game ', roomName, ' connection');
                if (gameMode === 'online')
                {
            		decoded_token = jwt_decode(getCookie('access_token'));
					sendGameMessage({
						action: 'get_state',
						canvas_width: canvasWidth,
						canvas_height: canvasHeight,
						player_id: decoded_token.user_id,
					});

					socketGame.onmessage = (event) => {
						const data = JSON.parse(event.data);

						if (data.status === 'disconnected') {
							console.log("Player disconnected");
							sendGameMessage({
								action: 'save_score',
								disconnected: 'yes',
								csrftoken: CSRFToken,
							});
							draw(data.state);
							isGameRunning = false;
						}
						else if (data.status === 'saved') {
							isGameRunning = false;
							resolve();
						}
						else if (data.status === 'state')
						{
							// console.log("State saved received : ", data.state.saved);
							if (data.state.saved === 1)
							{
								isGameRunning = false;
								resolve();
								return;
							}
							else
							{
            					decoded_token = jwt_decode(getCookie('access_token'));
								sendGameMessage({
									action: 'deconnection',
									canvas_width: canvasWidth,
									canvas_height: canvasHeight,
									player_id: decoded_token.user_id,
								});
							}
						}
					};
                }
                else
                {
                    socketGame.close();
					resolve();
                }
            }
        });
    }

/************************************************************************************************ */
/*                                   GAME MANAGEMENT                                              */
/************************************************************************************************ */

    function keyDownHandler(e)
	{
        if (e.key === 'w' || e.key === 'W') {
            wPressed = true;
        }
        if (e.key === 's' || e.key === 'S') {
            sPressed = true;
        }
        if (e.key === 'ArrowUp') {
            upPressed = true;
        }
        if (e.key === 'ArrowDown') {
            downPressed = true;
        }
    }

    function keyUpHandler(e)
	{
        if (e.key === 'w' || e.key === 'W') {
            wPressed = false;
        }
        if (e.key === 's' || e.key === 'S') {
            sPressed = false;
        }
        if (e.key === 'ArrowUp') {
            upPressed = false;
        }
        if (e.key === 'ArrowDown') {
            downPressed = false;
        }
    }

    function draw(state)
	{
        // if (!context || !canvas) {
        //     console.error('Context or canvas is not defined');
        //     return;
        // }
    
        context.clearRect(0, 0, canvas.width, canvas.height);
    
		// Draw the background image
        if (backgroundImage.complete) {
            context.drawImage(backgroundImage, 0, 0, canvas.width, canvas.height);
        } else {
            backgroundImage.onload = function() {
                context.drawImage(backgroundImage, 0, 0, canvas.width, canvas.height);
            }
        }

		// Draw the countdown text
		if (state.seconds > 0)
		{
			context.font = "48px Arial";
			context.fillStyle = "#FFF";
			context.textAlign = "center";
			context.fillText(state.seconds, canvas.width / 2, canvas.height / 2 - 2 * state.ball.radius);
		}

		// Draw the paddles
        if (state.paddle_left && state.paddle_right)
		{
            context.fillStyle = "#fff";
            context.fillRect(10, state.paddle_left.y, state.paddle_left.width, state.paddle_left.height);
            context.fillRect(canvas.width - 20, state.paddle_right.y, state.paddle_right.width, state.paddle_right.height);
        }
    
		// Draw the ball
        if (state.ball)
		{
            context.save();
            context.translate(state.ball.x + state.ball.radius / 2, state.ball.y + state.ball.radius / 2);
            context.rotate(state.ball.rotation_angle);
            context.drawImage(ballImage, -state.ball.radius / 2, -state.ball.radius / 2, state.ball.radius, state.ball.radius);
            context.restore();
        }
    
		// Draw the user names
		context.font = "40px Arial";
		context.textAlign = "left";
		context.fillText(state.player_left, 50, 50);
		context.textAlign = "right";
		context.fillText(state.player_right, canvas.width - 50, 50);

		// Draw the score
        context.font = "40px Arial";
        context.textAlign = "left";
        context.fillText(state.score_left, 50, 100);
        context.textAlign = "right"
        context.fillText(state.score_right, canvas.width - 50, 100);
    
        // Draw the number of ready players
        context.font = "40px Arial";
        context.textAlign = "center";
        if (!players_ready && gameMode === 'online')
        {
            context.fillText("Waiting for players...", canvas.width / 2, canvas.height - 80);
            context.fillText(state.ready_players + " / 2", canvas.width / 2, canvas.height - 20);
        }

		// Draw the game over text
        if (state.end_game === 1)
		{
            context.font = "50px Arial";
            context.textAlign = "center";
            if (state.forfeit === 0)
                context.fillText(state.winner + " won the game", canvas.width / 2, canvas.height / 2 - 2 * state.ball.radius);
            else if (state.forfeit === 1)
                context.fillText(state.winner + " won the game by forfeit", canvas.width / 2, canvas.height / 2 - 2 * state.ball.radius);
        }
    }

    function updateGame()
	{
        if (!isGameRunning) {
            return;
        }
        sendGameMessage({
            action: 'update',
            up_pressed: upPressed,
            down_pressed: downPressed,
            w_pressed: wPressed,
            s_pressed: sPressed,
            player_name: decoded_token.nickname,
            player_id: decoded_token.user_id,
        });
    }

    function gameLoop()
	{
        if (!isGameRunning) {
            return;
        }
        updateGame();
        // draw(currentState);
        requestAnimationFrame(gameLoop);
    }

    window.addEventListener('resize', resizeCanvas);
    document.addEventListener('keydown', keyDownHandler);
    document.addEventListener('keyup', keyUpHandler);


	function getCookie(name) {
        const cookieValue = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
        return cookieValue ? cookieValue.pop() : '';
    }


/************************************************************************************************ */
/*                                  TOURNAMENT                                                    */
/************************************************************************************************ */

    function resetTournament()
    {
        tournamentIsRunning = false;
        tournamentScores = [[0,0], [0,0], [0,0], [0,0], [0,0], [0,0], [0,0]];
        tournamentPlayers = [];
        tournamentRound2Players = [];
        tournamentRound3Players = [];
        tournamentNextRoundPlayers = [];
        tournamentRound = 1;
        tournamentMatch = 1;
        tournamentWinner = '';
		if (socketTournament && socketTournament.readyState === WebSocket.OPEN) {
			socketTournament.close();
		}
    }

    function checkPlayerNames()
    {
        if (player1 && player2 && player3 && player4 && player5 && player6 && player7 && player8)
        {
            return true;
        }
        return false;
    }

    function checkUniquePlayerNames() {
        const players = [player1, player2, player3, player4, player5, player6, player7, player8];
        const uniquePlayers = new Set(players);
        return uniquePlayers.size === players.length;
    }

    function createTournament(roomTournamentName, player1, player2, player3, player4, player5, player6, player7, player8)
    {
        decoded_token = jwt_decode(getCookie('access_token'));
        return new Promise((resolve, reject) => {
            initializeTournamentWebSocket(roomTournamentName)
            .then(() => {
                sendTournamentMessage({
                    action: 'create',
                    room: roomTournamentName,
                    player1: player1,
                    player2: player2,
                    player3: player3,
                    player4: player4,
                    player5: player5,
                    player6: player6,
                    player7: player7,
                    player8: player8
                });
                resolve();
            })
            .catch(error => {
                console.error("WebSocket Tournament connection failed: ", error);
                reject(error);
            });
        });
    }

	document.getElementById('content').addEventListener('click', function (event) {
        const createTurnBtn = event.target.closest('#createTurnBtn');
        if (createTurnBtn)
        {
            // console.log("createTurnBtn clicked");
            player1 = document.getElementById('player1').value;
            player2 = document.getElementById('player2').value;
            player3 = document.getElementById('player3').value;
            player4 = document.getElementById('player4').value;
            player5 = document.getElementById('player5').value;
            player6 = document.getElementById('player6').value;
            player7 = document.getElementById('player7').value;
            player8 = document.getElementById('player8').value;

            roomTournamentName = Math.random().toString(36).substring(2, 6) + Math.random().toString(36).substring(2, 6);
            if (roomTournamentName)
            {
                if (checkPlayerNames())
                {
                    if (checkUniquePlayerNames())
                    {
                        createTournament(roomTournamentName, player1, player2, player3, player4, player5, player6, player7, player8)
                        .then(() => {
                            console.log("Tournament created");
                        })
                        .catch((error) => {
                            console.log('Tournament creation failed', error);
                        });
                    }
                    else
                    {
                        alert("Player names must be unique.");
                    }
                }
                else
                {
                    alert('Please enter all player names');
                }


            }
            else
            {
                console.log('Problem occured when creating the tournament');
            }
        }
    });

    function displayTournamentPlayers(players)
    {
        loadContent("/game/tournament/" + roomTournamentName + "/", "content")
        .then(content => {
            const url = "/game/tournament/room/";
        });
    }

    function displayCountdownTournament(seconds) {
        return new Promise((resolve, reject) => {
            let remaining = seconds;

            const countdownInterval = setInterval(() => {
				console.log("Exiting in : ", remaining);
                // drawCountdown(remaining);
                remaining--;

                if (remaining < 0) {
                    clearInterval(countdownInterval);
                    socketGame.close();
                    resolve();
                }
                if (socketGame.readyState === WebSocket.CLOSED) {
                    clearInterval(countdownInterval);
                    reject();
                }
            }, 1000);
        });
    }
    document.getElementById('content').addEventListener('click', function (event) {
        const nextMatch = event.target.closest('#nextMatch');
        if (nextMatch)
        {
            decoded_token = jwt_decode(getCookie('access_token'));
            // console.log("Next match button clicked");
            roomName = Math.random().toString(36).substring(2, 6) + Math.random().toString(36).substring(2, 6);
            if (roomName)
            {
                if (tournamentPlayers.length >= 2)
                {
                    if (tournamentMatch === 5)
                        tournamentRound = 2;
                    else if (tournamentMatch === 7)
                        tournamentRound = 3;
                    else if (tournamentMatch === 8)
                        tournamentRound = 4;
                    if (tournamentMatch < 5)
                    {
                        i = (tournamentMatch - 1) * 2;
                        j = (tournamentMatch - 1) * 2 + 1;
                    }
                    else if (tournamentMatch < 7)
                    {
                        i = (tournamentMatch - 5) * 2;
                        j = (tournamentMatch - 5) * 2 + 1;
                    }
                    else if (tournamentMatch < 8)
                    {
                        i = (tournamentMatch - 7) * 2;
                        j = (tournamentMatch - 7) * 2 + 1;
                    }
                    tournamentMatch++;
                    if (tournamentRound === 1)
                    {
                        sendTournamentMessage({
                            action: 'next_match',
                            room: roomTournamentName,
                            player1: tournamentPlayers[i],
                            player2: tournamentPlayers[j],
                        });
                        loadContent("/game/local/", "content")
                        .then(content => {
                            const url = "/game/tournament/room/";
                            launchLocalGame(tournamentPlayers[i], tournamentPlayers[j], 'tournament');
                            // tournamentRound2Players.push(tournamentPlayers[i]);
                        })
                        .catch((error) => {
                            console.log('Tournament match failed', error);
                        });
                    }
                    else if (tournamentRound === 2)
                    {
                        sendTournamentMessage({
                            action: 'next_match',
                            room: roomTournamentName,
                            player1: tournamentRound2Players[i],
                            player2: tournamentRound2Players[j],
                        });
                        loadContent("/game/local/", "content")
                        .then(content => {
                            const url = "/game/local";
                            // history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/game/'
                            launchLocalGame(tournamentRound2Players[i], tournamentRound2Players[j], 'tournament');
                            // tournamentRound3Players.push(tournamentRound2Players[i]);
                        })
                        .catch((error) => {
                            console.log('Tournament match failed', error);
                        });
                    }
                    else if (tournamentRound === 3)
                    {
                        sendTournamentMessage({
                            action: 'next_match',
                            room: roomTournamentName,
                            player1: tournamentRound3Players[i],
                            player2: tournamentRound3Players[j],
                        });
                        loadContent("/game/local/", "content")
                        .then(content => {
                            const url = "/game/local";
                            // history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/game/'
                            launchLocalGame(tournamentRound3Players[i], tournamentRound3Players[j], 'tournament');
                            // tournamentWinner = tournamentRound3Players[i];
                            tournamentRound = 4;
                        })
                        .catch((error) => {
                            console.log('Tournament match failed', error);
                        });
                    }
                    else if (tournamentRound === 4)
                    {
                        console.log("Tournament winner : ", tournamentWinner);
                        winnerDiv = document.getElementById('winnerDiv')
                        winnerDiv.style.display = 'flex';
                    }
                }
                else
                {
                    alert('Not enough players to start the next match');
                }
            }
            else
            {
                console.log('Problem occured when starting the next match');
            }
        }
    });

    function initializeTournamentWebSocket() {
        socketTournament = new WebSocket('wss://' + window.location.hostname + ':8000/ws/tournament/' + roomTournamentName + '/');
        
        return new Promise((resolve, reject) => {
            socketTournament.onopen = () => {
                tournamentIsRunning = true;
                console.log('WebSocket Tournament connection opened');
                resolve();
            };

            socketTournament.onerror = (error) => {
                console.error('WebSocket Tournament error: ', error);
                tournamentIsRunning = false;
                reject(error);
            };

            socketTournament.onmessage = (event) =>
            {
                const data = JSON.parse(event.data);

                if (data.status === 'tournament_created') {

                    tournamentPlayers = data.players;
                    displayTournamentPlayers(data.players);
                    // console.log("Retour : ", data.players);
                }
                else if (data.status === 'match')
                {
                    console.log("Match : ", data.message);
                }
                else if (data.status === 'winner')
                {
                    console.log("Winner : ", data.message);
                }
                // else if (data.status === 'started') {
                //     console.log("Tournament started");
                // }
                // else if (data.status === 'ended') {
                //     console.log("Tournament ended");
                // }
                // else if (data.status === 'error') {
                //     console.error("Tournament error: ", data.message);
                // }
            }

            socketTournament.onclose = () => {
                console.log('WebSocket Tournament connection closed');
                tournamentIsRunning = false;
                isGameRunning = false;
            };

            window.addEventListener('beforeunload', () => {
                tournamentIsRunning = false;
                socketTournament.close();
            });
        });
    }

    function sendTournamentMessage(message)
	{
        if (socketTournament && socketTournament.readyState === WebSocket.OPEN) {
            socketTournament.send(JSON.stringify(message));
        } else {
            console.error("WebSocket Tournament is not open. Ready state: ", socketGame ? socketGame.readyState : 'no socket');
        }
    }

}