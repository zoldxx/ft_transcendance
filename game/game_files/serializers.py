from rest_framework import serializers
from .models import Game
from typing import Dict, Any

class HistoricSerializer(serializers.ModelSerializer):
    class Meta:
        model = Game
        fields = ['player1_id', 'player2_id', 'player1_score', 'player2_score', 'player1_nick', 'player2_nick', 'created_at']




# class Historicerializer(serializers.ModelSerializer):
#     formatted_created_at = serializers.SerializerMethodField()

#     class Meta:
#         model = Game
#         fields = '__all__'

#     def get_formatted_created_at(self, obj):
#         return obj.created_at.strftime('%d/%m/%Y %H:%M')


