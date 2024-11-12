document.addEventListener('DOMContentLoaded', function ()
{
	const accessToken = getCookie('access_token');
	const usernameSmallElement = document.getElementById('usernameSmall');
    const usernameElement = document.getElementById('username');
    const profileLink = document.getElementById('profileLink');
    const profileLinkSmall = document.getElementById('profileLinkSmall');
	const profileImage = document.getElementById('profileImage');
	const profileImageSmall = document.getElementById('profileImageSmall');
	let friendlist = 'close'
	let script;
	let canvas;
	let context;
	const backgroundImage = new Image();
	let lastCookies = getCookie('access_token');
    backgroundImage.src = '/static/game/images/brakmar_terrain_correct.png';

	class TokenExpiredError extends Error {
		constructor(message) {
			super(message);
			this.name = "TokenExpiredError";
		}
	}
	
	addEventListener('popstate', function (event) {
		loadContent(location.pathname, 'content');
	});

	if (accessToken) {
		try {
            const decodedToken = jwt_decode(accessToken);
			if (decodedToken)
			{
				if (isTokenExpired(accessToken) > 0)
					throw new TokenExpiredError('Token has expired');
				if (usernameSmallElement) {
					usernameSmallElement.textContent = decodedToken.nickname || 'Login';
				}
				if (usernameElement) {
					usernameElement.textContent = decodedToken.nickname || 'Login';
				}
				if (profileLink) {
					profileLink.href = '/profile/';
				}
				if (profileLinkSmall) {
					profileLinkSmall.href = '/profile/';
				}
				if (profileImage) {
					profileImage.src = decodedToken.profile_image_url;
					profileImage.style.display = 'inline';
				}
				if (profileImageSmall) {
					profileImageSmall.src = decodedToken.profile_image_url;
					profileImageSmall.style.display = 'inline';
				}
			}
		}
		catch (e) {
            if (e instanceof TokenExpiredError)
			{
				refreshAccessToken();
            }
        }
    }

	function resizeCanvas(roomName)
	{
        const gameContainer = document.getElementById('game');
		if (!gameContainer) {
			console.error('Game container not found');
			return;
		}
		canvas = document.getElementById('pongCanvas');
		context = canvas.getContext('2d');
        canvas.width = gameContainer.clientWidth;
        canvas.height = gameContainer.clientHeight;
        canvasWidth = canvas.width;
        canvasHeight = canvas.height;
	}

    function loadContent(url, targetElementId)
    {
		const accesstoken = getCookie('access_token');
		if (accesstoken)
		{
			fetch(url, {
				headers: {
					'Authorization': accesstoken,
					'Content-Type': 'text/html'
				},
				cookies: {
					'access_token': getCookie('access_token'),
				}
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
				const content = doc.querySelector('#content') ? doc.querySelector('#content').innerHTML : html;
				document.getElementById(targetElementId).innerHTML = content;
				if (url.includes('/game/')) {
					// Dynamically load pong.js only for the game page
					const decodedToken = jwt_decode(getCookie('access_token'));
					if (!script && decodedToken) {
						loadGameScript();
					}
					if (url.includes('/game/local/'))
					{
						resizeCanvas();
						if (backgroundImage.complete) {
							context.drawImage(backgroundImage, 0, 0, canvas.width, canvas.height);
						} else {
							backgroundImage.onload = function() {
								context.drawImage(backgroundImage, 0, 0, canvas.width, canvas.height);
							}
						}
					}
				}
			})
			.catch(error => console.log('Error:', error));
		}
		else
		{
			loadwithouttoken(url, targetElementId);
		}
    }

	function loadwithouttoken(url, targetElementId)
    {
		fetch(url, {
			headers: {
				'Content-Type': 'text/html'
			},
		})
		.then(response => response.text())
		.then(html => {
			const parser = new DOMParser();
			const doc = parser.parseFromString(html, 'text/html');
			const content = doc.querySelector('#content') ? doc.querySelector('#content').innerHTML : html;
			document.getElementById(targetElementId).innerHTML = content;
		})
		.catch(error => console.log('Error:', error));
	}

// UTILS


    function getCookie(name) {
        const cookieValue = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
        return cookieValue ? cookieValue.pop() : '';
    }

    function setCookie(name, value, days) {
        var expires = "";
        if (days) {
            var date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "")  + expires + "; path=/; secure; SameSite=Strict";
    }
	
	function isTokenExpired(accessToken) {
		const decodedToken = jwt_decode(accessToken);
		const currentTime = Math.floor(Date.now() / 1000);
		return decodedToken.exp - 60 < currentTime;
	}

	function deleteCookie(name) {
		document.cookie = name + '=; Max-Age=-99999999;';
	}

	function refreshAccessToken() {
		return new Promise((resolve, reject) => {
			const refreshToken = getCookie('refresh_token');
			const accessToken = getCookie('access_token');
			if (!refreshToken) {
				if (accessToken)
					deleteCookie('access_token')
				reject();
				return;
			}
			fetch('/refresh-token/', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': getCookie('csrftoken')
				},
				body: JSON.stringify({refresh_token: refreshToken}),
			})
			.then(response => response.json())
			.then(data => {
				if (data.access)
				{
					setCookie('access_token', data.access, 30);
					resolve();
				}
			})
			.catch(error => {
				console.error('Error refreshing token:', error)
				reject(error);
			});
		});
	}

	setInterval(() => {
		const token = getCookie('access_token');
		if (token && isTokenExpired(token))		
			refreshAccessToken();
		try
		{
			if (friendlist == 'open' && document.activeElement['id'] != 'nickAddUser' && document.getElementById('nickAddUser').value == "")
			{	
				console.log("test")
				loadContent('/friendlist/', 'friendlist')
			}
		}
		catch(e){}
	}, 5000);

		// UTILS
		
    function clearContent(containerId) {
		document.getElementById(containerId).innerHTML = '';
    }
	
	// Charge le contenu de la page active lors du chargement initial
	loadContent(location.pathname, 'content');
	
	// NAVBAR
	
    document.querySelectorAll('a.nav-link').forEach(link => {
		link.addEventListener('click', function (event) {
			event.preventDefault();
            const url = this.href;
            const targetElementId = 'content';
            loadContent(url, targetElementId);
            if (url !== location.pathname) {
                history.pushState(null, '', url);
			window.dispatchEvent(new Event('moveurl'));
        }
    });
});
	
	// CHARGER GAMESCRIPT	
	
	function loadGameScript() {
		// Load pong.js dynamically
		script = document.createElement('script');
		script.src = '/static/game/js/pong.js';
		script.onload = function() {
			console.log('pong.js loaded successfully');
			initializePong(); // Call initialization after loading pong.js
		};
		document.body.appendChild(script);
	}
	
	// BOUTONS DE HOME
	
    document.getElementById('content').addEventListener('click', function (event) {
		const loadSettingsBtn = event.target.closest('#loadSettingsBtn');
        if (loadSettingsBtn) {
			if (loadSettingsBtn.classList.contains('active')) {
				// Si le bouton est déjà actif, désactive l'affichage en supprimant la classe 'active'
                loadSettingsBtn.classList.remove('active');
                // Efface le contenu dynamique
                clearContent('dynamicContent');
            } else {
				// Si le bouton n'est pas actif, active l'affichage en ajoutant la classe 'active'
                loadSettingsBtn.classList.add('active');
                // Charge le contenu dynamique
                loadContent('/settings/', 'dynamicContent');
            }
            // const url = '/home/';
            // history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/home/contact/'
        }
    });
	
	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#loadPlayBtn');
		if (loadPlayBtn) {
			loadContent('/game/', 'content'); 
			const url = '/game/';
            history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/game/'
		}
	}); 

	function getCsrfToken() {
		// Exemple : récupérer le token CSRF depuis un cookie
		const cookies = document.cookie.split(';');
		let csrfToken = '';
		cookies.forEach(cookie => {
			const [name, value] = cookie.trim().split('=');
			if (name === 'csrftoken') { // Assurez-vous que le nom correspond à celui de votre cookie CSRF
				csrfToken = value;
			}
		});
		return csrfToken;
	}
	
	// USER MANAGEMENT
	
	document.getElementById('content').addEventListener('click', function (event) {
		const friendUserBtn = event.target.closest('[id^="friendUserBtn"]');
		if (friendUserBtn) {
			const userId = friendUserBtn.getAttribute('friend-id');
			loadContent(`/users/${userId}/`, 'content');
			const url = `/users/${userId}/`;
            history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/home/contact/'
		}
	});
    
    document.getElementById('content').addEventListener('click', function (event) {
		const userBtn = event.target.closest('[id^="userBtn"]');
		if (userBtn) {
			const userId = userBtn.getAttribute('user-id');
			loadContent(`/users/${userId}/`, 'content');
			const url = `/users/${userId}/`;
            history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/home/contact/'
		}
	});

	// EDIT LOGIN

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#editLoginBtn');
		if (loadPlayBtn) {
			let currentUrl = window.location.href;
			if (currentUrl.includes('change_avatar/')) 
			{ currentUrl = currentUrl.replace('change_avatar/', 'change_nickname/');}
			else
				currentUrl += 'change_nickname/';
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});
	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#cancelEditLogin');
		if (loadPlayBtn) {

			let currentUrl = window.location.href;
			if (currentUrl.includes('change_nickname/')) {
				currentUrl = currentUrl.replace('change_nickname/', '');
			}
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#ChangeLoginBtn');
		url = window.location.href;
		if (loadPlayBtn) {
			event.preventDefault();
			const formData = new FormData(editNicknameForm); 
			fetch(url, {
				method: 'POST',
				body: formData,
				headers: {
					'X-CSRFToken': getCookie('csrftoken'),
					// 'X-CSRFToken': getCsrfToken(),
				}
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
				const contentTemplate = doc.querySelector('#content');
				if (contentTemplate) {
					refreshAccessToken()
					.then(() => {
						access_Token = getCookie('access_token');
						if (access_Token) {
							try {
								const decodedToken = jwt_decode(access_Token);
								if (decodedToken)
								{
									if (isTokenExpired(access_Token))
										throw new TokenExpiredError('Token has expired');
									if (usernameSmallElement) {
										usernameSmallElement.textContent = decodedToken.nickname || 'Login';
									}
									if (usernameElement) {
										usernameElement.textContent = decodedToken.nickname || 'Login';
									}
									if (profileLink) {
										profileLink.href = '/profile/';
									}
									if (profileLinkSmall) {
										profileLinkSmall.href = '/profile/';
									}
									if (profileImage) {
										profileImage.src = decodedToken.profile_image_url;
										profileImage.style.display = 'inline';
									}
									if (profileImageSmall) {
										profileImageSmall.src = decodedToken.profile_image_url;
										profileImageSmall.style.display = 'inline';
									}
								}
							}
							catch (e) {
								if (e instanceof TokenExpiredError)
								{
									refreshAccessToken();
								}
							}
						}
					})
					.catch(error => {
						console.error("Refresh token failed: ", error);
					});
					document.getElementById('content').innerHTML = contentTemplate.innerHTML;
					message = doc.getElementById('message');
					text_msg = message.textContent;
					if (url.includes('change_nickname/') && text_msg == 'Nickname changed.') {
						const url = '/profile/';
						history.pushState(null, '', url);
					}
				} else {
					console.error('Content element not found in response.');
				}
			})
			.catch(error => console.error('Error:', error));
		}
	});

	// EDIT AVATAR

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#editAvatarBtn');
		if (loadPlayBtn) {
			let currentUrl = window.location.href;
			if (currentUrl.includes('change_nickname/')) 
				{currentUrl = currentUrl.replace('change_nickname/', 'change_avatar/');}
			else
				currentUrl += 'change_avatar/';
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#cancelEditAvatar');
		if (loadPlayBtn) {

			let currentUrl = window.location.href;
			if (currentUrl.includes('change_avatar/')) {
				currentUrl = currentUrl.replace('change_avatar/', '');
			}
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#ChangeAvatarBtn');
		url = window.location.href;
		if (loadPlayBtn) {
			event.preventDefault();
			const formData = new FormData(editAvatarForm); 
			fetch(url, {
				method: 'POST',
				body: formData,
				headers: {
					'X-CSRFToken': getCookie('csrftoken'),
					// 'X-CSRFToken': getCsrfToken(),
				}
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
				const contentTemplate = doc.querySelector('#content');
				if (contentTemplate) {
					refreshAccessToken()
					.then(() => {
						access_Token = getCookie('access_token');
						if (access_Token) {
							try {
								const decodedToken = jwt_decode(access_Token);
								if (decodedToken)
								{
									if (isTokenExpired(access_Token))
										throw new TokenExpiredError('Token has expired');
									if (usernameSmallElement) {
										usernameSmallElement.textContent = decodedToken.nickname || 'Login';
									}
									if (usernameElement) {
										usernameElement.textContent = decodedToken.nickname || 'Login';
									}
									if (profileLink) {
										profileLink.href = '/profile/';
									}
									if (profileLinkSmall) {
										profileLinkSmall.href = '/profile/';
									}
									if (profileImage) {
										profileImage.src = decodedToken.profile_image_url;
										profileImage.style.display = 'inline';
									}
									if (profileImageSmall) {
										profileImageSmall.src = decodedToken.profile_image_url;
										profileImageSmall.style.display = 'inline';
									}
								}
							}
							catch (e) {
								if (e instanceof TokenExpiredError)
								{
									refreshAccessToken();
								}
							}
						}
					})
					.catch(error => {
						console.error("Refresh token failed: ", error);
					});
					document.getElementById('content').innerHTML = contentTemplate.innerHTML;
					message = doc.getElementById('message_avatar');
					text_msg = message.textContent;
					if (url.includes('change_avatar/') && text_msg == 'avatar changed.') {
						url = url.replace('change_avatar/', '');
						history.pushState(null, '', url);
					}
				} else {
					console.error('Content element not found in response.');
				}
			})
			.catch(error => console.error('Error:', error));
		}
	});

	// EDIT PASSWORD

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#editPassword');
		if (loadPlayBtn) {
			let currentUrl = window.location.href;
			if (currentUrl.includes('change_nickname/')) 
				{currentUrl = currentUrl.replace('change_nickname/', 'change_password/');}
			else if (currentUrl.includes('change_avatar/')) 
				{currentUrl = currentUrl.replace('change_avatar/', 'change_password/');}
			else
				currentUrl += 'change_password/';
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#cancelEditPassword');
		if (loadPlayBtn) {

			let currentUrl = window.location.href;
			if (currentUrl.includes('change_password/')) {
				currentUrl = currentUrl.replace('change_password/', '');
			}
			loadContent(currentUrl,'content');
			history.pushState(null, '', currentUrl);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const loadPlayBtn = event.target.closest('#ChangePasswordBtn');
		url = window.location.href;
		if (loadPlayBtn) {
			event.preventDefault();
			const formData = new FormData(editPasswordForm); 
			fetch(url, {
				method: 'POST',
				body: formData,
				headers: {
					'X-CSRFToken': getCookie('csrftoken'),
					// 'X-CSRFToken': getCsrfToken(),
				}
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
				const contentTemplate = doc.querySelector('#content');
				if (contentTemplate) {
					document.getElementById('content').innerHTML = contentTemplate.innerHTML;
					message = doc.getElementById('message_password');
					text_msg = message.textContent;
					if (url.includes('change_password/') && text_msg == 'Password changed.') {
						url = url.replace('change_password/', '');
						//loadContent(url,'content');
						history.pushState(null, '', url);
					}
				} else {
					console.error('Content element not found in response.');
				}
			})
			.catch(error => console.error('Error:', error));
		}
	});

	// LOGIN
	
	document.getElementById('content').addEventListener('click', function(event) {
		const loginBtn = event.target.closest('#loginBtn');
		if (loginBtn) {
			event.preventDefault();
			const loginForm = document.getElementById('loginForm');
			const usernameField = loginForm.querySelector('input[name="username"]');
			const passwordField = loginForm.querySelector('input[name="password"]');
			const usernameError = document.getElementById('usernameError');
			const passwordError = document.getElementById('passwordError');
			const profileImage = document.getElementById('profileImage');
			const profileImageSmall = document.getElementById('profileImageSmall');
			// Reset error messages and set input fields to white background
			usernameError.textContent = '';
			passwordError.textContent = '';// Set password field background to white
			
			let isValid = true;
			if (usernameField.value.trim() === '') {
				usernameError.textContent = 'Username is required';
				isValid = false;
			}
			if (passwordField.value.trim() === '') {
				passwordError.textContent = 'Password is required';
				isValid = false;
			}
			
			if (isValid) {
				const formData = new FormData(loginForm);
				const url = loginForm.getAttribute('action');
				
				fetch('/login/', {
					method: 'POST',
					body: formData,
					headers: {
						'X-CSRFToken': getCookie('csrftoken'),
					},
				})
				.then(response => response.text())
				.then(html => {
					const parser = new DOMParser();
					const doc = parser.parseFromString(html, 'text/html');
					
					// Extract elements from the HTML response
					const contentTemplate = doc.querySelector('#content');
					const accessToken = doc.querySelector('meta[name="access_token"]');
					const refreshToken = doc.querySelector('meta[name="refresh_token"]');
					const nickname = doc.querySelector('meta[name="nickname"]');
					const username = doc.querySelector('meta[name="username"]');
					const message = doc.querySelector('meta[name="message"]');
					const secretKey = doc.querySelector('meta[name="double_auth_key"]');
					const usernameSmallElement = document.getElementById('usernameSmall');
					const usernameElement = document.getElementById('username');
					// console.log("usernameSmallElement", usernameSmallElement);
					const profileLink = document.getElementById('profileLink');
					// console.log("profileLink", profileLink);
					const profileLinkSmall = document.getElementById('profileLinkSmall');
					// console.log("profileLinkSmall", profileLinkSmall);
					const successIndicatorElement = doc.querySelector('#registerStatus');
					// Update cookies
					if (accessToken && refreshToken && successIndicatorElement) {
						setCookie('access_token', accessToken.content, 30);
						setCookie('refresh_token', refreshToken.content, 30);			
						//localStorage.setItem('access_token', accessToken.content);
                    	//localStorage.setItem('refresh_token', refreshToken.content);

						decodedToken = jwt_decode(accessToken.content)
						if (usernameSmallElement) {
							usernameSmallElement.textContent = decodedToken.nickname  || 'Login';
						}
						if (usernameElement) {
							usernameElement.textContent = decodedToken.nickname  || 'Login';
						}
						if (profileLink) {
							profileLink.href = '/profile/';
						}
						if (profileLinkSmall) {
							profileLinkSmall.href = '/profile/';
						}
						if (profileImage) {
							profileImage.src = decodedToken.profile_image_url;
							profileImage.style.display = 'inline';
						}
						if (profileImageSmall) {
							profileImageSmall.src = decodedToken.profile_image_url;
							profileImageSmall.style.display = 'inline';
						}
						const url = '/home/';
						history.pushState(null, '', url);
					}
					else if (!successIndicatorElement)
					{
						if (nickname) {
							let existingMeta = document.querySelector('meta[name="nickname"]');
							if (!existingMeta) {
								existingMeta = document.createElement('meta');
								existingMeta.setAttribute('name', 'nickname');
								document.head.appendChild(existingMeta);
							}
							existingMeta.setAttribute('content', username.content);
						}
						if (secretKey) {
							let existingMeta = document.querySelector('meta[name="double_auth_key"]');
							if (!existingMeta) {
								existingMeta = document.createElement('meta');
								existingMeta.setAttribute('name', 'double_auth_key');
								document.head.appendChild(existingMeta);
							}
							existingMeta.setAttribute('content', secretKey.content);
						}
						if (accessToken) {
							let existingMeta = document.querySelector('meta[name="access_token"]');
							if (!existingMeta) {
								existingMeta = document.createElement('meta');
								existingMeta.setAttribute('name', 'access_token');
								document.head.appendChild(existingMeta);
							}
							existingMeta.setAttribute('content', accessToken.content);
						}
						if (refreshToken) {
							let existingMeta = document.querySelector('meta[name="refresh_token"]');
							if (!existingMeta) {
								existingMeta = document.createElement('meta');
								existingMeta.setAttribute('name', 'refresh_token');
								document.head.appendChild(existingMeta);
							}
							existingMeta.setAttribute('content', refreshToken.content);
						}
					}
					// Update content
					if (contentTemplate) {
						document.getElementById('content').innerHTML = contentTemplate.innerHTML;
					} else {
						console.error('Content element not found in response.');
					}
	
					// Update message element and set color to red
					const messageElement = document.getElementById('messageElement');
					if (messageElement && message && message.content) {
						messageElement.textContent = message.content;
						messageElement.style.color = 'red'; // Set message text color to red
					}
				})
				.catch(error => console.error('Error:', error));
			}
		}
	});
			
	document.getElementById('openFriendlistButton').addEventListener('click', function(event) {
		const openButton = event.target.closest('#openFriendlistButton');
		try
		{
			if (openButton && !isTokenExpired(getCookie('access_token')))
			{
				loadContent('/friendlist/', 'friendlist');
				friendlist = 'open';
			}
		}
		catch(e){}
	});
	
	document.getElementById('friendlist').addEventListener('click', function(event) {
		const closeButton = event.target.closest('#closeFriendlistButton');
		if (closeButton) {
			clearContent('friendlist');
			friendlist = 'close';
		}
	});

	document.getElementById('friendlist').addEventListener('click', function (event) {
		const addFriendButton = event.target.closest('#addFriendButton');
		if (addFriendButton) {
			const name = document.getElementById('nickAddUser').value
			if (name)
			{
				data={'name': name}
				fetch('/addFriend/', {
					method: 'POST',
					headers: {
						'Authorization': getCookie('access_token'),
						'X-CSRFToken': getCookie('csrftoken'),
						'Content-Type': 'text/html'
					},
					cookies: {'access_token': getCookie('access_token')},
					body: JSON.stringify(data)
				})
				.then(response => response.json)
				.then(data => {
					var inputElement = document.getElementById('nickAddUser');
					document.getElementById('nickAddUser').value = "";
					loadContent('/friendlist/', 'friendlist')
				})
				.catch(error => console.log('Error:', error));
			}
		}
	});
	document.getElementById('friendlist').addEventListener('click', function (event) {
		const handleRequestButton = event.target.closest('.friendlist-btn');
		if (handleRequestButton)
		{
			const fromUserId = handleRequestButton.getAttribute('data-from-user-id');
			const toUserId = handleRequestButton.getAttribute('data-to-user-id');
			const action = handleRequestButton.innerText.trim().toLowerCase(); // 'cancel', 'accept', 'decline'
			

			fetch('/handleRequest/', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': getCookie('csrftoken')
				},
				cookies: {'access_token': getCookie('access_token')},
				body: JSON.stringify({
					action: action,
					from_user_id: fromUserId,
					to_user_id: toUserId
				})
			})
			.then(response => response.json())
			.then(data => {
				console.log(data);
				// Gérer la réponse ici si nécessaire
				loadContent('/friendlist/', 'friendlist')
			})
			.catch(error => {console.error('Error:', error)});
		}
	});
			
	// REGISTER
	
	document.getElementById('content').addEventListener('click', function (event) {
		const register42Btn = event.target.closest('#register42Btn');
		if (register42Btn) {
			console.log("register42clic");
			fetch('/login-with-42/', {
				method: 'POST',
				headers: {
					'Authorization': getCookie('access_token'),
					'X-CSRFToken': getCookie('csrftoken'),
					'Content-Type': 'text/html'
				},
				cookies: {'access_token': getCookie('access_token')},
			})
			.then(response => response.json)
			.then(data => {
				console.log("data=", data);
			})
		}
	})

	document.addEventListener('content', function () {
		function showError(message) {
			return new Promise((resolve, reject) => {
				console.log("ici")
				const errorMessageDiv = document.getElementById('error-message');
				console.log(errorMessageDiv)
				if (errorMessageDiv) {
					console.log("la")
					errorMessageDiv.innerHTML = `<div class="alert alert-danger">${message}</div>`;
					resolve();
				} else {
					console.log("ok")
					reject(new Error('Error message div not found'));
				}
			});
		}

		// Obtenez les paramètres de l'URL
		const urlParams = new URLSearchParams(window.location.search);
		const errorMessage = urlParams.get('error');

		// Affichez le message d'erreur si disponible
		if (errorMessage) {
			showError(errorMessage).catch(error => console.error('Failed to display error:', error));
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const gotoRegisterBtn = event.target.closest('#gotoRegister');
		if (gotoRegisterBtn) {
			loadContent('/register/', 'content'); 
			const url = '/register/';
			history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/home/contact/'
		}
	}); 
	
	document.getElementById('content').addEventListener('click', function (event) {
		const registerBtn = event.target.closest('#registerBtn');
		if (registerBtn) {
			console.log("register");
			event.preventDefault();
			const form = document.getElementById('RegisterForm');
			const formData = new FormData(form);
	
			fetch(form.action, {
				method: 'POST',
				body: formData,
				headers: {
					'X-CSRFToken': getCsrfToken(),
				}
			})
			.then(response => response.text())
			.then(html => {
				const parser = new DOMParser();
				const doc = parser.parseFromString(html, 'text/html');
	
				// Check for the message in the response
				const message = doc.querySelector('meta[name="message"]');
				if (message) {
					const messageContent = message.getAttribute('content');
					console.log("message", messageContent);
	
					// Update the messageElement with the message content
					document.getElementById('messageElement').textContent = messageContent;
					document.getElementById('messageElement').style.color = 'red'; // Optional: style the message
				} else {
					console.error('Meta message not found in response.');
				}
	
				// Handle other elements if necessary
				const accessToken = doc.querySelector('meta[name="access_token"]');
				const refreshToken = doc.querySelector('meta[name="refresh_token"]');
				const nickname = doc.querySelector('meta[name="nickname"]');
				const username = doc.querySelector('meta[name="username"]');
				const usernameSmallElement = document.getElementById('usernameSmall');
				const usernameElement = document.getElementById('username');
				const profileLink = document.getElementById('profileLink');
				const profileLinkSmall = document.getElementById('profileLinkSmall');
				if (accessToken && refreshToken) {
					setCookie('access_token', accessToken.getAttribute('content'), 30);
					setCookie('refresh_token', refreshToken.getAttribute('content'), 30);
					decodedToken = jwt_decode(accessToken.content)
					if (usernameSmallElement) {
						usernameSmallElement.textContent = nickname.getAttribute('content') || 'Login';
					}
					if (usernameElement) {
						usernameElement.textContent = nickname.getAttribute('content') || 'Login';
					}
					if (profileLink) {
						profileLink.href = '/profile/';
					}
					if (profileLinkSmall) {
						profileLinkSmall.href = '/profile/';
					}
					if (profileImage) {
						profileImage.src = decodedToken.profile_image_url;
						profileImage.style.display = 'inline';
					}
					if (profileImageSmall) {
						profileImageSmall.src = decodedToken.profile_image_url;
						profileImageSmall.style.display = 'inline';
					}
				}
	
				if (message && message.getAttribute('content') === 'User registered successfully') {
					console.log("User registered successfully");
					loadContent('/home/', 'content');
					const url = '/home/';
					history.pushState(null, '', url);
					//window.location.href = '/home/';
				}
			})
			.catch(error => console.error('Error:', error));
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const gotoRegisterBtn = event.target.closest('#gotoRegister');
		if (gotoRegisterBtn) {
			loadContent('/register/', 'content'); 
			const url = '/register/';
			history.pushState(null, '', url); // Ajoute une nouvelle entrée dans l'historique de navigation avec l'URL '/home/contact/'
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const backtologin = event.target.closest('#backtologin');
		if (backtologin) {
			console.log('Activate backtologin2F button clicked!');
			event.preventDefault();
			loadContent('/login/', 'content');
			const url = '/login/';
			history.pushState(null, '', url);
		}

	});

	document.getElementById('content').addEventListener('click', function (event) {
		const logout = event.target.closest('#logout');
		if (logout) {
			console.log('Activate logout button clicked!');
			event.preventDefault();
			
			// Récupérer le token d'accès et le token CSRF
			const accessToken = document.cookie.split(';').find(cookie => cookie.trim().startsWith('access_token='));
			const jwtToken = accessToken ? accessToken.split('=')[1] : null;
			const csrftoken = getCookie('csrftoken');
			
			if (!jwtToken) {
				console.log('Access token missing');
				return;
			}
			
			// Effectuer la requête fetch
			fetch('/logout_view/', {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${jwtToken}`,
					'X-CSRFToken': csrftoken,
					'Content-Type': 'application/json'
				},
				credentials: 'include',
				body: JSON.stringify({})
			})
			.then(response => {
				console.log('Response Status:', response.status);  // Affiche le statut de la réponse
				if (!response.ok) {
					return response.text().then(text => {
						throw new Error(`Error: ${text}`);
					});
				}
				return response.text();  // Utilisez text() pour voir la réponse brute
			})
			.then(text => {
				// console.log('Response Body:', text);  // Affiche le corps de la réponse
				// Supprimer les cookies après une réponse réussie
				if (friendlist == 'open')
				{
					clearContent('friendlist');
					friendlist = 'close';
				}
				deleteCookie('access_token');
				deleteCookie('refresh_token');
				const profileImage = document.getElementById('profileImage');
				const profileImageSmall = document.getElementById('profileImageSmall');
				const profileLink = document.getElementById('profileLink');
				const profileLinkSmall = document.getElementById('profileLinkSmall');
				const decodedToken = jwt_decode(accessToken);

				if (usernameSmallElement) {
					usernameSmallElement.textContent = 'Login';
				}
				if (usernameElement) {
					usernameElement.textContent = 'Login';
				}
				if (profileLink) {
					profileLink.href = '/login/';
				}
				if (profileLinkSmall) {
					profileLinkSmall.href = '/login/';
				}
				if (profileImage) {
					profileImage.src = decodedToken.profile_image_url;
					profileImage.style.display = 'None';
				}
				if (profileImageSmall) {
					profileImageSmall.src = decodedToken.profile_image_url;
					profileImageSmall.style.display = 'None';
				}
				// Rediriger après la déconnexion
				loadContent('/login/', 'content');
				const url = '/login/';
				history.pushState(null, '', url);
			})
			.catch(error => {
				console.error('There was a problem with the fetch operation:', error);
			});
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const activateA2FBtn = event.target.closest('#activateA2FBtn');
		if (activateA2FBtn) {
			console.log('Activate A2F button clicked!');
			event.preventDefault();
			
			const accessToken = document.cookie.split(';').find(cookie => cookie.trim().startsWith('access_token='));
			const jwtToken = accessToken ? accessToken.split('=')[1] : null;

			if (!jwtToken) {
				console.log('Access token missing');
				return;
			}
			
			// Générer le QR code et charger le contenu
			generateQrCode(jwtToken, function(img) {
				loadContentAndDisplayQrCode('/activea2f/', 'content', img);
			});
		}
	});
	
	function generateQrCode(jwtToken, callback) {
		fetch('/generate-qr-code/', {
			method: 'GET',
			headers: {
				'Authorization': `Bearer ${jwtToken}`
			},
			credentials: 'include'
		})
		.then(response => {
			if (!response.ok) {
				throw new Error('Erreur réseau');
			}
			return response.blob();
		})
		.then(blob => {
			const img = document.createElement('img');
			img.style.width = '150px';
			img.style.height = '150px';
			img.src = URL.createObjectURL(blob);
			img.onload = function() {
				callback(img);
			};
		})
		.catch(error => console.error('Error:', error));
	}
	
	function loadContentAndDisplayQrCode(url, containerId, img) {
				fetch(url, {
					headers: {
						'Authorization': getCookie('access_token'),
					},
					cookies: {
						'access_token': getCookie('access_token'),
					}
				})
        .then(response => {
			if (!response.ok) {
				throw new Error('Erreur réseau lors du chargement du contenu');
            }
            return response.text();
        })
        .then(html => {
			const parser = new DOMParser();
			const doc = parser.parseFromString(html, 'text/html');
			const content = doc.querySelector('#content') ? doc.querySelector('#content').innerHTML : html;
			document.getElementById('content').innerHTML = content;

            // Maintenant que le contenu est chargé, ajouter le QR code
            const qrContainer = document.querySelector('#qrcode');
            if (qrContainer) {
                qrContainer.appendChild(img);
            }
			
            // Afficher le bouton de vérification
            const verifyCodeBtn = document.getElementById('verifyCodeBtn');
            if (verifyCodeBtn) {
				verifyCodeBtn.style.display = 'block';
            }
        })
        .catch(error => {
			console.error('Error loading content:', error);
            throw error;
        });
		
	}
	
	document.getElementById('content').addEventListener('click', function (event) {
		const activateA2FBtn = event.target.closest('#verifyCodeBtn');
		if (activateA2FBtn) {
			if (!document.querySelector('#codeInput')) {
				const codeInputForm = document.createElement('form');
				codeInputForm.innerHTML = `
					<input type="text" id="codeInput" maxlength="6" placeholder="Enter 6-digit code" required class="form-control white-text custom-input">
					<button type="submit" id="submitCodeBtn" class="custom-button-form custom-button">Submit</button>
				`;
		
				activateA2FBtn.style.display = 'none';
				document.getElementById('activateA2FContainer').appendChild(codeInputForm);
		
				codeInputForm.addEventListener('submit', function (submitEvent) {
					submitEvent.preventDefault();
					const codeInputValue = document.getElementById('codeInput').value;
					const accessToken = document.cookie.split(';').find(cookie => cookie.trim().startsWith('access_token='));
					const jwtToken = accessToken ? accessToken.split('=')[1] : null;
		
					fetch('/verify_code/', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'Authorization': jwtToken ? `Bearer ${jwtToken}` : undefined,
							'X-CSRFToken': getCookie('csrftoken')
						},
						body: JSON.stringify({ code: codeInputValue }),
						credentials: 'same-origin',
					})
					.then(response => {
						if (!response.ok) {
							throw new Error('Network response was not ok');
						}
						return response.json();
					})
					.then(data => {
						if (data.success) {
							console.log("Code verified successfully");
		
							alert('Code verified successfully!');
							// fetch('/verify_code/', {
							// 	method: 'POST',
							// 	headers: {
							// 		'Content-Type': 'application/json',
							// 		'Authorization': jwtToken ? `Bearer ${jwtToken}` : undefined,
							// 	},
							// 	body: JSON.stringify({ code: codeInputValue }),
							// 	credentials: 'same-origin',
							// })
							loadContent('/profile/', 'content');
						} else {
							alert('Invalid code. Please try again.');
						}
					})
					.catch(error => {
						console.error('Error:', error);
						alert('An error occurred. Please try again later.');
					});
				});
			}
		}
	});
	
	document.getElementById('content').addEventListener('click', function (event) {
		const btnLocal = event.target.closest('#homeLocalBtn');
		if (btnLocal) {
			
			event.preventDefault();
			const url = "/game/local/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const btnTournament = event.target.closest('#homeTournamentBtn');
		if (btnTournament) {	
			event.preventDefault();
			const url = "/game/tournament/room/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const btnOnline = event.target.closest('#homeOnlineBtn');
		if (btnOnline) {	
			event.preventDefault();
			const url = "/game/online/room/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const btnOnline = event.target.closest('#backHomeBtn1');
		if (btnOnline) {	
			event.preventDefault();
			window.dispatchEvent(new Event('moveurl'));
			const url = "/home/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const btnOnline = event.target.closest('#backHomeBtn2');
		if (btnOnline) {	
			event.preventDefault();
			window.dispatchEvent(new Event('moveurl'));
			const url = "/home/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	document.getElementById('content').addEventListener('click', function (event) {
		const btnOnline = event.target.closest('#backHomeBtn3');
		if (btnOnline) {	
			event.preventDefault();
			window.dispatchEvent(new Event('moveurl'));
			const url = "/home/";
			loadContent(url, "content");
			history.pushState(null, '', url);
		}
	});

	// Fonction pour gérer la vérification du code de connexion
	document.getElementById('content').addEventListener('click', function (event) {
		const btn = event.target.closest('#submitCodeA2fBtn');	
		if (btn) {
			event.preventDefault();
			const codeInputValue = document.getElementById('codeA2fInput').value;

			// Récupérer le login depuis les métadonnées

			const loginMeta = document.querySelector('meta[name="nickname"]');
			const login = loginMeta ? loginMeta.content : null;
			const secretKeyMeta = document.querySelector('meta[name="double_auth_key"]');
			const secret_key = secretKeyMeta ? secretKeyMeta.content : null;
			const accessTokenMeta = document.querySelector('meta[name="access_token"]');
			const refreshTokenMeta = document.querySelector('meta[name="refresh_token"]');
			const profileImage = document.getElementById('profileImage');
			const profileImageSmall = document.getElementById('profileImageSmall');
			decodedToken = jwt_decode(accessTokenMeta.content)
			fetch('/verify_login_code/', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': getCookie('csrftoken')
					
				},
				body: JSON.stringify({ code: codeInputValue, accessToken: accessTokenMeta ? accessTokenMeta.content : null, secret_key: secret_key}),
				credentials: 'same-origin',
			})
			.then(response => {
				if (!response.ok) {
					throw new Error('Network response was not ok');
				}
				return response.json();
			})
			.then(data => {
				if (data.success) {
					document.getElementById('usernameSmall').textContent = decodedToken.nickname;
					document.getElementById('username').textContent = decodedToken.nickname;
					document.getElementById('profileLink').href = '/profile/';
					document.getElementById('profileLinkSmall').href = '/profile/';
					setCookie('access_token', accessTokenMeta.content, 30);
					setCookie('refresh_token', refreshTokenMeta.content, 30);	
					decodedToken = jwt_decode(accessTokenMeta.content)
					if (profileImage) {
						profileImage.src = decodedToken.profile_image_url;
						profileImage.style.display = 'inline';
					}
					if (profileImageSmall) {
						profileImageSmall.src = decodedToken.profile_image_url;
						profileImageSmall.style.display = 'inline';
					}
					const url = "/home/";
					loadContent('/home/', 'content');
					history.pushState(null, '', url);
					alert('Code verified successfully!');
				} else {
					alert('Invalid code. Please try again.');
				}
			})
			.catch(error => {
				console.error('Error:', error);
				alert('An error occurred. Please try again later.');
			});
		}
	});
	
});	

document.getElementById('content').addEventListener('click', function (event) {
	const loadPlayBtn = event.target.closest('#WinBtn');
	if (loadPlayBtn) {
		var maDiv = document.getElementById('winnerDiv');
		 maDiv.style.display = 'flex'; // Rendre la div visible

		// Déclenche l'animation après que la div soit visible
		setTimeout(function() {
			maDiv.classList.add('show');
		}, 50); // Délai pour permettre au navigateur de rendre la div visible
	}
});