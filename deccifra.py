import requests
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

autor_pesq = input('Digite o ID da mensagem que deseja buscar: ')
url = f"https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens/{autor_pesq}"

response = requests.get(url)

if response.status_code == 200:
    msg = response.json()

    try:
        mensagem_bytes = base64.b64decode(msg['texto'])
        assinatura_bytes = base64.b64decode(msg['assinatura'])
        public_pem_bytes = base64.b64decode(msg['publicKey'])

        public_key = serialization.load_pem_public_key(public_pem_bytes)

        public_key.verify(
            assinatura_bytes,
            mensagem_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        mensagem = mensagem_bytes.decode('utf-8')
        print(f"✔ Mensagem ID {autor_pesq} - Assinatura válida!")
        print("Mensagem:", mensagem)

    except Exception as e:
        print("❌ Assinatura inválida ou erro:", e)

else:
    print(f"Mensagem com ID {autor_pesq} não encontrada. Código:", response.status_code)
