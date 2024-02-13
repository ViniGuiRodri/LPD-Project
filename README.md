# LPD-Project
Welcome to Vtool Script Project!

<img src="/Images/LPD-Project.png" width="800">


## Manual do Usuário para o Programa LPD-Project.py
Este manual fornece instruções passo a passo para utilizar o programa de segurança de rede e
criptografia. Siga as orientações para instalar as bibliotecas necessárias e operar cada
funcionalidade do programa.


## Instalação das Bibliotecas Necessárias
Antes de começar, certifique-se de instalar as seguintes bibliotecas no Kali Linux usando os comandos:

Scapy para manipulação de pacotes:
    pip install scapy

Pycryptodome para criptografia:
    pip install pycryptodome

Cryptography para funções criptográficas avançadas:
    pip install cryptography


## Menu do Programa
    1- Port Scan
    2- UDP Flood
    3- SYN Flood
    4- Troca de Mensagens (Versão Alternativa Externa)
    5- Troca de Mensagens
    6- Client Port Knocking
    7- (Adicional) Reverse Shell


## Funcionalidades do Programa
1. Port Scan
Objetivo: Identificar portas abertas em uma faixa de IPs.
Como usar: Escolha a opção 1 no menu e forneça o IP alvo e o intervalo de portas a serem verificadas.
Para escanear somente uma porta utilize da seguinte forma “192.168.0.1 22 - 22”, para a porta 22 no caso.
    
2. Flood UDP
Objetivo: Enviar uma grande quantidade de pacotes UDP para um IP alvo.
Como usar: Escolha a opção 2 e insira o IP alvo.

3. SYN Flood
Objetivo: Realizar um ataque de inundação SYN para testar a resiliência de um servidor.
Como usar: Selecione a opção 3 e informe o IP e a porta alvo.

4. Troca de Mensagens
Objetivo: Trocar mensagens criptografadas entre um cliente e um servidor.
Como usar: Escolha a opção 5 e siga as instruções para configurar o servidor ou o cliente.

5. Troca de Mensagens Alternativo
Acesse o programa externo “Troca de Mensagens”.

6. Port Knocking
Objetivo: Acessar serviços ocultos por meio de uma sequência específica de portas.
Como usar: Selecione a opção 6, digite o endereço IP do servidor alvo e as portas para a sequência de knocking.

7. (Adicional) Reverse Shell
Objetivo: Obter controle remoto de um sistema.
Como usar: Acesse a opção 7 para instruções detalhadas.


## Navegação no Menu
Execute o programa. O menu principal será exibido automaticamente.
Digite o número correspondente à funcionalidade desejada e pressione Enter.
Siga as instruções específicas de cada funcionalidade.
Para sair do programa, escolha a opção 0.

## Observações Importantes
Utilize este programa responsavelmente e apenas em redes e sistemas para os quais você tem permissão explícita para testar.