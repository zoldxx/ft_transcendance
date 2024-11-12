# game/models.py
from django.db import models
from django.conf import settings

class Game(models.Model):
    player1_id = models.IntegerField()
    player2_id = models.IntegerField()
    player1_nick = models.CharField(default='bontarien')
    player2_nick = models.CharField(default='brakmarien')
    player1_score = models.IntegerField()
    player2_score = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Game {self.id}: Player 1 ({self.player1_id}) vs Player 2 ({self.player2_id})"
