from django.http import JsonResponse
from .models import Game
from .serializers import HistoricSerializer
from django.db.models import Q

def historic(request):
    historic = Game.objects.all()
    historic_serializer = HistoricSerializer(historic, many=True)
    return JsonResponse(historic_serializer.data, safe=False)

def historic_profile(request, id):

    historic = Game.objects.filter(Q(player1_id=id) | Q(player2_id=id))
    historic_serializer = HistoricSerializer(historic, many=True)  
    return JsonResponse(historic_serializer.data, safe=False)


