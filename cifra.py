import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Ler chave privada para assinar
with open(r"C:\Users\diogo\Desktop\chaves\chave_privada.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Ler as chaves públicas e guardar os bytes e objetos
with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Diogo.pem", "rb") as f:
    public_pem_Diogo = f.read()
    public_key_Diogo = serialization.load_pem_public_key(public_pem_Diogo)

with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Miguel.pem", "rb") as f:
    public_pem_Miguel = f.read()
    public_key_Miguel = serialization.load_pem_public_key(public_pem_Miguel)

with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Filipa.pem", "rb") as f:
    public_pem_Filipa = f.read()
    public_key_Filipa = serialization.load_pem_public_key(public_pem_Filipa)

# Perguntar ao utilizador qual chave pública quer usar para enviar
print("Escolhe a chave pública para incluir na mensagem:")
print("1 - Diogo")
print("2 - Miguel")
print("3 - Filipa")
escolha = input("Digite 1, 2 ou 3: ")
2
if escolha == "1":
    public_pem_bytes = public_pem_Diogo
    autor = "Diogo"
elif escolha == "2":
    public_pem_bytes = public_pem_Miguel
    autor = "Miguel"
elif escolha == "3":
    public_pem_bytes = public_pem_Filipa
    autor = "Filipa"
else:
    print("Escolha inválida! Vai usar a chave do Diogo por defeito.")
    public_pem_bytes = public_pem_Diogo
    autor = "Diogo"

# Ler a mensagem a enviar
mensagem = input("Digita uma mensagem: ")
mensagem_bytes = mensagem.encode()

# Assinar mensagem com a chave privada
assinatura = private_key.sign(
    mensagem_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)
assinatura_b64 = base64.b64encode(assinatura).decode()

# Codificar a mensagem em base64
mensagem_b64 = base64.b64encode(mensagem_bytes).decode()

# Preparar payload para enviar à API
payload = {
    "createdAt": datetime.now().strftime("%d/%m/%Y %H:%M"),
    "texto": mensagem_b64,
    "autor": autor,
    "assinatura": assinatura_b64,
    "publicKey": base64.b64encode(public_pem_bytes).decode()
}

# URL da API
url = "https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens/"

# Enviar POST
response = requests.post(url, json=payload)

if response.status_code in [200, 201]:
    print("✅ Mensagem enviada com sucesso!")
else:
    print("❌ Erro ao enviar mensagem:", response.status_code, response.text)
