import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Ler chave privada do ficheiro para assinar
with open(r"C:\Users\diogo\Desktop\chaves\chave_privada.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 2. Lê a chave pública de um ficheiro
with open(r"C:\Users\diogo\Desktop\chaves\chave_publica.pem", "rb") as f:
    public_pem_str = f.read()


# 3. Carrega a chave pública do texto inserido
public_key = serialization.load_pem_public_key(public_pem_str)

# 4. Mensagem a enviar
mensagem = "Esta é uma mensagem secreta que vou assinar."
mensagem_bytes = mensagem.encode()

# 5. Assinar mensagem com chave privada
assinatura = private_key.sign(
    mensagem_bytes,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
assinatura_b64 = base64.b64encode(assinatura).decode()

# 6. Codificar mensagem para base64
mensagem_b64 = base64.b64encode(mensagem_bytes).decode()

# 7. Preparar payload para enviar à API
payload = {
    "createdAt": datetime.now().strftime("%d/%m/%Y %H:%M"),
    "texto": mensagem_b64,
    "autor": "Diogo",
    "assinatura": assinatura_b64,
    "publicKey": base64.b64encode(public_pem_str).decode(), 
}

# 8. URL da API 
url = "https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens/"

# 9. Enviar POST
response = requests.post(url, json=payload)

if response.status_code in [200, 201]:
    print("Mensagem enviada com sucesso!")
else:
    print("Erro ao enviar mensagem:", response.status_code, response.text)
