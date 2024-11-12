# game/game_logic.py

import random

import time

def start_game_logic(state, data):
    state['canvas'] = {
        'width': data.get('canvas_width'),
        'height': data.get('canvas_height')
    }
    reset_positions(state, data)
    state['score_left'] = 0
    state['score_right'] = 0
    state['winner'] = None
    state['forfeit'] = 0
    state['end_game'] = 0
    state['seconds'] = 0
    state['ready_players'] = 0
    state['saved'] = 0

    if data.get('game_mode') == 'online':
        state['game_mode'] = data.get('game_mode')
        if data.get('player_nick'):
            state['player_left'] = data.get('player_nick')
        else:
            state['player_left'] = "undefined"
        state['player_left_id'] = data.get('player_id')
        state['player_right_id'] = None
        state['player_right'] = "Waiting for player..."

    elif data.get('game_mode') == 'local':
        state['game_mode'] = data.get('game_mode')
        state['player_left'] = data.get('player1')
        state['player_right'] = data.get('player2')
        state['player_left_id'] = None
        state['player_right_id'] = None
    elif data.get('game_mode') == 'tournament':
        state['game_mode'] = data.get('game_mode')
        state['player_left'] = data.get('player1')
        state['player_right'] = data.get('player2')
        state['player_left_id'] = None
        state['player_right_id'] = None

def add_second_player(state, data):
    if data.get('player_nick'):
        state['player_right'] = data.get('player_nick')
    else:
        state['player_right'] = "undefined"
    state['player_right_id'] = data.get('player_id')

def reset_positions(state, data):
    radius = 20
    state['canvas'] = {
        'width': data.get('canvas_width'),
        'height': data.get('canvas_height')
    }
    state['paddle_left'] = {
        'x': 10,
        'y': data.get('canvas_height') / 2 - 50,
        'width': 10,
        'height': 100
    }
    state['paddle_right'] = {
        'x': data.get('canvas_width') - 20,
        'y': data.get('canvas_height') / 2 - 50,
        'width': 10,
        'height': 100
    }
    state['ball'] = {
        'radius': radius,
        'x': state['canvas']['width'] / 2 - radius / 2,
        'y': state['canvas']['height'] / 2 - radius / 2,
        'speed_x': random.choice([state['canvas']['width'] / 300, -state['canvas']['width'] / 300]),
        'speed_y': random.uniform(-2.5, 2.5) or 1,
        'acceleration': state['canvas']['width'] / 2000,
        'rotation_angle': -2,
        'rotation_speed': random.uniform(-5, 5),  # Initial rotation speed based on the initial speed
    }

def update_rotation_speed(ball):
    # Update the rotation speed based on the ball's speed
    speed_magnitude = (ball['speed_x'] ** 2 + ball['speed_y'] ** 2) ** 0.5
    ball['rotation_speed'] = speed_magnitude / 50

def update_game_logic(state, data):
    # # Gérer le décompte avant le début du jeu
    # if state['countdown'] > 0:
    #     elapsed_time = time.time() - state['countdown_start_time']
    #     state['countdown'] = max(0, 3 - int(elapsed_time))
    #     if state['countdown'] == 0:
    #         state['countdown_start_time'] = None
    #     return  # Ne pas continuer la mise à jour du jeu si le décompte est actif

    paddle_speed = state['canvas']['height'] / 150
    canvas_height = state['canvas']['height']
    canvas_width = state['canvas']['width']

    up_pressed = data.get('up_pressed', False)
    down_pressed = data.get('down_pressed', False)
    w_pressed = data.get('w_pressed', False)
    s_pressed = data.get('s_pressed', False)

    # Mise à jour des palettes
    if (state['game_mode'] == 'local' or state['game_mode'] == 'tournament'):
        if w_pressed:
            state['paddle_left']['y'] = max(0, state['paddle_left']['y'] - paddle_speed)
        if s_pressed:
            state['paddle_left']['y'] = min(canvas_height - state['paddle_left']['height'], state['paddle_left']['y'] + paddle_speed)
        if up_pressed:
            state['paddle_right']['y'] = max(0, state['paddle_right']['y'] - paddle_speed)
        if down_pressed:
            state['paddle_right']['y'] = min(canvas_height - state['paddle_right']['height'], state['paddle_right']['y'] + paddle_speed)
    elif (state['game_mode'] == 'online'):
        if state['player_left_id'] == data.get('player_id'):
            if w_pressed:
                state['paddle_left']['y'] = max(0, state['paddle_left']['y'] - paddle_speed)
            if s_pressed:
                state['paddle_left']['y'] = min(canvas_height - state['paddle_left']['height'], state['paddle_left']['y'] + paddle_speed)
        elif state['player_right_id'] == data.get('player_id'):
            if w_pressed:
                state['paddle_right']['y'] = max(0, state['paddle_right']['y'] - paddle_speed)
            if s_pressed:
                state['paddle_right']['y'] = min(canvas_height - state['paddle_right']['height'], state['paddle_right']['y'] + paddle_speed)

    # Mise à jour de la balle
    ball = state['ball']

    # Fait en sorte que la balle soit déplacée uniquement par le joueur de gauche
    if state['player_left_id'] == data.get('player_id') or state['game_mode'] == 'local' or state['game_mode'] == 'tournament':
        # Vérifie la collision avec la raquette gauche
        if ball['x'] + ball['speed_x'] <= state['paddle_left']['x'] + state['paddle_left']['width']:
            if state['paddle_left']['y'] <= ball['y'] + ball['radius'] / 2 <= state['paddle_left']['y'] + state['paddle_left']['height']:
                ball['x'] = state['paddle_left']['x'] + state['paddle_left']['width']
                ball['speed_x'] = -ball['speed_x'] + ball['acceleration']
                
                # Calculer l'offset de collision
                relative_intersect_y = (state['paddle_left']['y'] + state['paddle_left']['height'] / 2) - (ball['y'] + ball['radius'] / 2)
                normalized_relative_intersect_y = (relative_intersect_y / (state['paddle_left']['height'] / 2))
                ball['speed_y'] = -normalized_relative_intersect_y * 5  # 5 est un facteur de vitesse ajustable

                ball['rotation_speed'] = -ball['rotation_speed']

        # Vérifie la collision avec la raquette droite
        if ball['x'] + ball['speed_x'] >= state['paddle_right']['x'] - ball['radius']:
            if state['paddle_right']['y'] <= ball['y'] + ball['radius'] / 2 <= state['paddle_right']['y'] + state['paddle_right']['height']:
                ball['x'] = state['paddle_right']['x'] - ball['radius']
                ball['speed_x'] = -ball['speed_x'] - ball['acceleration']

                # Calculer l'offset de collision
                relative_intersect_y = (state['paddle_right']['y'] + state['paddle_right']['height'] / 2) - (ball['y'] + ball['radius'] / 2)
                normalized_relative_intersect_y = (relative_intersect_y / (state['paddle_right']['height'] / 2))
                ball['speed_y'] = -normalized_relative_intersect_y * 5  # 5 est un facteur de vitesse ajustable

                ball['rotation_speed'] = -ball['rotation_speed']

        ball['x'] += ball['speed_x']
        ball['y'] += ball['speed_y']

        # Met à jour la vitesse de rotation après la mise à jour des vitesses
        update_rotation_speed(state['ball'])

        # Collision avec le haut et le bas
        if state['ball']['y'] <= 0 or state['ball']['y'] >= canvas_height - state['ball']['radius']:
            state['ball']['speed_y'] = -state['ball']['speed_y']

        # Rotation de la balle
        state['ball']['rotation_angle'] += state['ball']['rotation_speed']

        # Compte des points
        if state['ball']['x'] + state['ball']['radius'] > state['paddle_right']['x']+ 1:
            state['score_left'] += 1
            state['paddle_left']['x'] = 10
            state['paddle_left']['y'] = state['canvas']['height'] / 2 - 50
            state['paddle_right']['x'] = state['canvas']['width'] - 20
            state['paddle_right']['y'] = state['canvas']['height'] / 2 - 50
            state['ball']['x'] = canvas_width / 2 - state['ball']['radius'] / 2
            state['ball']['y'] = canvas_height / 2 - state['ball']['radius'] / 2
            state['ball']['speed_y'] = random.uniform(-2.5, 2.5) or 1
            state['ball']['speed_x'] = state['canvas']['width'] / 300

        if state['ball']['x'] <= state['paddle_left']['x'] + 1:
            state['score_right'] += 1
            state['paddle_left']['x'] = 10
            state['paddle_left']['y'] = state['canvas']['height'] / 2 - 50
            state['paddle_right']['x'] = state['canvas']['width'] - 20
            state['paddle_right']['y'] = state['canvas']['height'] / 2 - 50
            state['ball']['x'] = canvas_width / 2 - state['ball']['radius'] / 2
            state['ball']['y'] = canvas_height / 2 - state['ball']['radius'] / 2
            state['ball']['speed_y'] = random.uniform(-2.5, 2.5) or 1
            state['ball']['speed_x'] = -state['canvas']['width'] / 300

    #Fin de partie à 3 buts
    if state['score_left'] == 3:
        state['winner'] = state['player_left']
        state['end_game'] = 1
    elif state['score_right'] == 3:
        state['winner'] = state['player_right']
        state['end_game'] = 1


def get_game_state(state):
    return {
        'paddle_left': state['paddle_left'],
        'paddle_right': state['paddle_right'],
        'ball': {
            'x': state['ball']['x'],
            'y': state['ball']['y'],
            'radius': state['ball']['radius'],
            'rotation_angle': state['ball']['rotation_angle'],
            'speed_x': state['ball']['speed_x']
        },
        'player_left': state['player_left'],
        'player_left_id': state['player_left_id'],
        'player_right': state['player_right'],
        'player_right_id': state['player_right_id'],
        'score_left': state['score_left'],
        'score_right': state['score_right'],
        'winner': state['winner'],
        'end_game': state['end_game'],
        'seconds': state['seconds'],
        'forfeit': state['forfeit'],
        'ready_players': state['ready_players'],
        'game_mode': state['game_mode'],
        'saved': state['saved']
    }
