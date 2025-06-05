import requests


autor_pesq = input('Digite o id da mensagem que deseja buscar: ')
url = "https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens/"


params = {
    "id": autor_pesq
}

