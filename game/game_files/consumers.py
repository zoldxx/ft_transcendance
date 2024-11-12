# srcs/game/game_files/consumers.py

import json
from channels.generic.websocket import WebsocketConsumer
from asgiref.sync import async_to_sync
from .game_logic import start_game_logic, update_game_logic,\
    get_game_state, add_second_player, reset_positions
from .models import Game
from django.conf import settings
import logging
import random
import requests
import bleach

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class GameConsumer(WebsocketConsumer):
    room_names = set()  # Class-level set to store room names
    rooms_clients_count = {}  # Class-level dictionary to track number of clients in each room
    rooms_states = {}  # Class-level dictionary to store game states for each room
    rooms_ready_clients = {}  # Class-level dictionary to store ready clients for each room
    
#************************************************************************************************ *#
#*                                   CONNECTIONS/RECEIVE                                          *#
#************************************************************************************************ *#
    def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'game_{self.room_name}'
        
        # Join room group
        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name,
            self.channel_name
        )

        self.ready_clients = set()

        self.accept()
        self.state = {}
        self.is_game_running = False
        # Update clients count for the room
        if self.room_group_name not in self.rooms_clients_count:
            self.rooms_clients_count[self.room_group_name] = 0
        self.rooms_clients_count[self.room_group_name] += 1

        # Initialize room state if it doesn't exist
        if self.room_group_name not in self.rooms_states:
            self.rooms_states[self.room_group_name] = {}

        # self.send_state('connected')


    def disconnect(self, close_code):
        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name,
            self.channel_name
        )
        if self.channel_name in self.ready_clients:
            self.ready_clients.remove(self.channel_name)

        # Update clients count for the room
        if self.room_group_name in self.rooms_clients_count:
            self.rooms_clients_count[self.room_group_name] -= 1
            if self.rooms_clients_count[self.room_group_name] <= 0:
                del self.rooms_clients_count[self.room_group_name]
                del self.rooms_states[self.room_group_name]
                self.send(text_data=json.dumps({
					'status': 'closeRoom',
					'message': 'Room is closed.'
				}))


    def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        if action == 'ready':
            self.handle_ready(data)
        elif action == 'initialize' and not self.is_game_running:
            self.initialize_game(data)
        elif action == 'start' and not self.is_game_running:
            self.is_game_running = True
            self.local_game(data)
        elif action == 'initialize_tournament':
            self.init_tournament_local(data)
        elif action == 'start_tournament':
            self.start_tournament_local(data)
        elif action == 'countdown':
            self.countdown(data)
        elif action == 'update':
            self.update_game(data)
        elif action == 'stop':
            self.stop_game(data)
        elif action == 'stop':
            self.stop_game(data)
        elif action == 'redraw':
            self.redraw_game(data)
        elif action == 'save_score':
            self.save_game_to_db(data)
        elif action == 'deconnection':
            self.deconnection(data)
        elif action == 'check_full':
            self.check_full(data)
        elif action == 'get_state':
            self.send_state('state')
        elif action == 'check_id':
            self.check_id(data)


#************************************************************************************************ *#
#*                                   LOCAL GAME MODE                                              *#
#************************************************************************************************ *#

    def local_game(self, data):
        self.state = {}
        start_game_logic(self.state, data)
        self.send_state('started')

    def init_tournament_local(self, data):
        self.state = {}
        start_game_logic(self.state, data)
        self.send_state('tournament_match_initialized')

    def start_tournament_local(self, data):
        self.send_state('started')

    def check_full(self, data):
        room_members = self.rooms_clients_count.get(self.room_group_name, 0)
        if room_members == 0 or room_members == 1 or room_members == 2:
            self.send(text_data=json.dumps({
                'status': 'not_full',
                'message': 'Room is not full.'
            }))
        elif room_members > 2:
            self.send(text_data=json.dumps({
                'status': 'full',
                'message': 'Too many players in the room.'
            }))

    def initialize_game(self, data):
        if self.room_group_name not in self.room_names:
            self.room_names.add(self.room_group_name)
        room_members = self.rooms_clients_count.get(self.room_group_name, 0)	
        if room_members == 1:
            start_game_logic(self.rooms_states[self.room_group_name], data)
        elif room_members == 3:
            add_second_player(self.rooms_states[self.room_group_name], data)
        self.send_state('initialized')
        
    def check_id(self, data):
        if self.rooms_states[self.room_group_name].get('player_left_id') == data.get('player_id'):
            self.send(text_data=json.dumps({
                'status': 'double',
                'message': 'Player left id checked.'
            }))
        else:
            self.send(text_data=json.dumps({
                'status': 'not_double',
                'message': 'Player left id not checked.'
            }))

    def handle_ready(self, data):
        # Add client to ready list
        if self.room_group_name not in self.rooms_ready_clients:
            self.rooms_ready_clients[self.room_group_name] = []
        if data.get('player_name') not in self.rooms_ready_clients[self.room_group_name]:
            self.rooms_ready_clients[self.room_group_name].append(data.get('player_name'))
            self.rooms_states[self.room_group_name]['ready_players'] += 1
        else:
            self.rooms_ready_clients[self.room_group_name].remove(data.get('player_name'))
            self.rooms_states[self.room_group_name]['ready_players'] -= 1
        
        # Send ready confirmation to client
        self.send_state('ready')

        # Check if all clients are ready to start game
        if self.all_clients_ready():
            self.start_game(data)

    def all_clients_ready(self):
        # Check if all clients in the room are ready
        return len(self.rooms_ready_clients[self.room_group_name]) >= 2
        # self.rooms_clients_count.get(self.room_group_name, 0)

    def start_game(self, data):
        self.ready_clients.clear()
        self.send_state('started')

    def countdown(self, data):
        if (self.state and (self.state['game_mode'] == 'local' or self.state['game_mode'] == 'tournament')):
            self.state['seconds'] = data.get('seconds')
        else:
            self.rooms_states[self.room_group_name]['seconds'] = data.get('seconds')
        self.send_state('countdown')

    def redraw_game(self, data):
        # if (self.state and self.state['game_mode'] == 'local'):
        #     reset_positions(self.state, data)
        # else:
        #     reset_positions(self.rooms_states[self.room_group_name], data)
        self.send_state('redraw')

    def update_game(self, data):
        if (self.state and (self.state['game_mode'] == 'local' or self.state['game_mode'] == 'tournament')):
            update_game_logic(self.state, data)
        else:
            update_game_logic(self.rooms_states[self.room_group_name], data)
        if self.state:
            if self.state['end_game'] == 1:
                self.send_state('stopped')
            else:
                self.send_state('updated')
        else:
            if self.rooms_states[self.room_group_name]['end_game'] == 1:
                self.send_state('stopped')
            else:
                self.send_state('updated')

    def stop_game(self, data):
        self.is_game_running = False
        if (self.state and self.state['game_mode'] == 'local'):
            start_game_logic(self.state, data)
        else:
            start_game_logic(self.rooms_states[self.room_group_name], data)
        self.send_state('stopped')

    def deconnection(self, data):
        if (self.state and (self.state['game_mode'] == 'local' or self.state['game_mode'] == 'tournament')):
            self.state['end_game'] = 1
        else:
            if (self.rooms_states[self.room_group_name]['saved'] == 1):
                return
            self.rooms_states[self.room_group_name]['forfeit'] = 1
            if (self.rooms_states[self.room_group_name]['player_left_id'] == data.get('player_id')):
                logger.error('Player left quit the game')
                self.rooms_states[self.room_group_name]['score_right'] = 3
                self.rooms_states[self.room_group_name]['score_left'] = 0
                self.rooms_states[self.room_group_name]['winner'] = self.rooms_states[self.room_group_name]['player_right']
            elif (self.rooms_states[self.room_group_name]['player_right_id'] == data.get('player_id')):
                self.rooms_states[self.room_group_name]['score_left'] = 3
                self.rooms_states[self.room_group_name]['score_right'] = 0
                self.rooms_states[self.room_group_name]['winner'] = self.rooms_states[self.room_group_name]['player_left']
                logger.error('Player right quit the game')
            self.rooms_states[self.room_group_name]['end_game'] = 1
            reset_positions(self.rooms_states[self.room_group_name], data)
            if self.room_group_name in self.rooms_clients_count:
                self.rooms_clients_count[self.room_group_name] -= 1
                if self.rooms_clients_count[self.room_group_name] <= 0:
                    del self.rooms_clients_count[self.room_group_name]
                    del self.rooms_states[self.room_group_name]
                self.send(text_data=json.dumps({
					'status': 'closeRoom',
					'message': 'Room is closed.',
					'room': self.room_name
				}))
            self.send_state('updated')
            self.send(text_data=json.dumps({
                'status': 'debug',
                'message': 'Player left the game.'
            }))
            self.send(text_data=json.dumps({
                'status': 'disconnected',
                'state': get_game_state(self.rooms_states[self.room_group_name])
            }))


    def send_state(self, status):
        if (self.state and (self.state['game_mode'] == 'local' or self.state['game_mode'] == 'tournament')):
            self.send(text_data=json.dumps({
                'status': status,
                'state': self.state
            }))
        else:
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name,
                {
                    'type': 'game_state',
                    'status': status,
                    'state': get_game_state(self.rooms_states[self.room_group_name])
                }
            )

    def game_state(self, event):
        status = event['status']
        state = event['state']

        self.send(text_data=json.dumps({
            'status': status,
            'state': state
        }))

    def save_game_to_db(self, data):
        if self.rooms_states[self.room_group_name].get('saved') == 1:
            return
        player1_id = self.rooms_states[self.room_group_name].get('player_left_id')
        player2_id = self.rooms_states[self.room_group_name].get('player_right_id')
        player1_nick = self.rooms_states[self.room_group_name].get('player_left')
        player2_nick = self.rooms_states[self.room_group_name].get('player_right')
        player1_score = self.rooms_states[self.room_group_name].get('score_left')
        player2_score = self.rooms_states[self.room_group_name].get('score_right')

        game = Game(
            player1_id=player1_id,
            player2_id=player2_id,
            player1_nick=player1_nick,
            player2_nick=player2_nick,
            player1_score=player1_score,
            player2_score=player2_score
        )
        game.save()
        # Send to usermanagement the winner and looser id to update winrate
        if (player1_score < player2_score):
            winner_id = player2_id
            loser_id = player1_id
        else:
            winner_id = player1_id
            loser_id = player2_id
        payload = {
            'winner_id': winner_id,
            'loser_id': loser_id
        }
        headers = {'X-CSRFToken': data.get('csrftoken')}
        cookies = {'csrftoken': data.get('csrftoken')}
        response = requests.post(
            'http://usermanagement:8003/winrate/',
            json=payload,
            headers=headers,
            cookies=cookies
        )
        self.rooms_states[self.room_group_name]['saved'] = 1
        self.send(text_data=json.dumps({
            'status': 'saved',
            'message': 'Game saved.'
        }))
        if (data.get('disconnected') == 'yes'):
            self.disconnect(1000)
            self.send(text_data=json.dumps({
                'status': 'close',
                'message': 'Game saved and close the websocket.'
            }))


#************************************************************************************************ *#
#*                                  ROOM WEB SOCKET MANAGEMENT                                    *#
#************************************************************************************************ *#

class RoomsConsumer(WebsocketConsumer):
    rooms_names = set()  # Class-level set to store room names

    def connect(self):

        self.accept()
        self.send(text_data=json.dumps({
                'status': 'connected',
                'message': 'You are connected.'
            }))

    def disconnect(self, close_code):
        pass


    def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')
        if action == 'add':
            self.add_room(data)
        elif action == 'delete':
            self.delete_room(data)
        elif action == 'check':
            self.check_room(data)

    def add_room(self, data):
        room_name = data.get('room_name')
        if room_name not in self.rooms_names:
            self.rooms_names.add(room_name)
            self.send(text_data=json.dumps({
                'status': 'added',
                'message': f'Room {room_name} added.',
                'room_name': room_name
            }))
        else:
            self.send(text_data=json.dumps({
                'status': 'creation_failed',
                'message': f'Room {room_name} already exists.',
                'room_name': room_name
            }))
            
    def delete_room(self, data):
        room_name = data.get('room_name')
        if room_name in self.rooms_names:
            self.rooms_names.remove(room_name)
            self.send(text_data=json.dumps({
                'status': 'deleted',
                'message': f'Room {room_name} deleted.',
                'room_name': room_name
            }))
        else:
            self.send(text_data=json.dumps({
                'status': 'error',
                'message': f'Room {room_name} does not exist.',
                'room_name': room_name
            }))
    
    def check_room(self, data):
        room_name1 = data.get('room_name')
        room_name = bleach.clean(room_name1)
        if room_name in self.rooms_names:
            self.send(text_data=json.dumps({
                'status': 'found',
                'message': f'Room {room_name} found.',
                'room_name': room_name
            }))
        else:
            self.send(text_data=json.dumps({
                'status': 'not_found',
                'message': f'Room {room_name} not found.',
                'room_name': room_name
            }))


#************************************************************************************************ *#
#*                                  TOURNAMENT                                                    *#
#************************************************************************************************ *#

class TournamentConsumer(WebsocketConsumer):
    rooms_names = set()  # Class-level set to store room names
    players = []
    player1 = None
    player2 = None
    player3 = None
    player4 = None
    player5 = None
    player6 = None
    player7 = None
    player8 = None

    def connect(self):

        self.accept()
        self.send(text_data=json.dumps({
                'status': 'connected',
                'message': 'You are connected.'
            }))

    def disconnect(self, close_code):
        pass


    def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        if action == 'create':
            self.set_players(data)
            self.create_tournament(self.players)
        elif action == 'start_tournament':
            self.delete_room(data)
        elif action == 'next_match':
            self.launch_match(data.get('player1'), data.get('player2'))

    def set_players(self, data):
        self.player1_nobleach = data.get('player1')
        self.player2_nobleach = data.get('player2')
        self.player3_nobleach = data.get('player3')
        self.player4_nobleach = data.get('player4')
        self.player5_nobleach = data.get('player5')
        self.player6_nobleach = data.get('player6')
        self.player7_nobleach = data.get('player7')
        self.player8_nobleach = data.get('player8')

        self.player1 = bleach.clean(self.player1_nobleach)
        self.player2 = bleach.clean(self.player2_nobleach)
        self.player3 = bleach.clean(self.player3_nobleach)
        self.player4 = bleach.clean(self.player4_nobleach)
        self.player5 = bleach.clean(self.player5_nobleach)
        self.player6 = bleach.clean(self.player6_nobleach)
        self.player7 = bleach.clean(self.player7_nobleach)
        self.player8 = bleach.clean(self.player8_nobleach)

        self.players = [self.player1, self.player2, self.player3, self.player4, self.player5, self.player6, self.player7, self.player8]


    def create_tournament(self, players):
        # Mélanger aléatoirement les joueurs
        random.shuffle(players)
        self.send(text_data=json.dumps({
            'status': 'tournament_created',
            'players': players
        }))

