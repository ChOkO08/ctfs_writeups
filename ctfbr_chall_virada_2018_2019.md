# CHALLENGE DA VIRADA (2018 -> 2019)

> Challenge da virada (2018 -> 2019)
> 
> Resolvido por: aguardando
> 
> Nome: Rootkit
> 
> Descrição: Suspeitamos que um de nossos servidores foi ownado pela Inteligência da Bloodsuckers. Tudo indica para o fato de terem instalado um binary rootkit em nosso sistema, visando conseguir nossas credenciais para tentarem usar em outros servidores. Faça uma análise forense no dump do sistema, e ao identificar o comprometimento, faça um reversing para identificar a senha que dá acesso ao dump (sniffer) das senhas. Após isso, entendendo o funcionamento do rk, obtenha a última senha legítima utilizada pelo root na máquina, pois achamos que ela foi mudada pelo pessoal da Inteligência por uma default deles, e também pode nos ser útil em outros dos seus sistemas, como a de dump! (o feitiço virou contra o feiticeiro!). Submeta no formato CTF-BR{SenhaUsadaParaDump,UltimaSenhaRootLegitima}. Não temos as credenciais, isso faz parte do desafio.
> 
> Categoria: Forensics
> 
> Link do arquivo: [aqui](https://static.pwn2win.party/2017/rootkit_3e4df5d6a3926cbc81ebf014a82098ad0964653aaedf581cd1bbc06eb3756642.tar.gz)
> 
> Write-up do vencedor: aguardando
> 
> Lançamento: 31 de dezembro de 2018
>
> Resolução: aguardando

**WRITE-UP**

Este ano o desafio do CTF-BR para o [Hall of Fame](https://ctf-br.org/hall-of-fame/) trouxe um desafio de forense bem interessante. Aparentemente um de nossos servidores foi ownado e pra melhorar instalaram um rootkit...!

[¬___¬'](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRlZRFJevs0yhUbh1NBE7QsxQ9VohUZ86ErbhudcxmxHi_15W7l "Malditos Hackers ¬__¬'")

O desafio nos pede para analisar o dump do sistema e determinar duas coisas:
  1. senha utilizada para dump, e;
  2. última senha root legítima.
 
Após o download primeiro verifiquei qual o tipo de arquivo:
[!File type](https://imgur.com/ffFO7Wi)

Fazendo jus à minha fama de desconfiado, também confiro o hash do arquivo:

[!...epa, hashes diferentes? Õ_õ...esse gnx eh f0dz -_-](https://imgur.com/FCx4Sip)

Como o challenge não informou as credenciais desta máquina, resolvi seguir duas abordagens:
  1. recuperar os arquivos da imagem dada utilizando o [photorec](https://www.cgsecurity.org/wiki/PhotoRec), e;
  2. alterar a senha do root para facilitar a análise _ao vivo_ da máquina.
  
## Recuperando arquivos com o photorec 

O photorec é excelente para recuperação de arquivos. Basta criar um diretório de saída para os arquivos recuperados e executa-lo passando o arquivo da imagem como parâmetro:

```shell
mkdir photo
photorec ub1404lts-disk1.vmdk
```

![photorec](https://imgur.com/g5N10lA)


Feito isso, o programa recuperou diversos arquivos e os dividiu em 29 diretórios (recup_dir.xx). A idéia era procurar por algum indicativo deste malware na imagem. Como não sabia o que procurar tentei a string 'rootkit' \o/!

![grep -ri rootkit](https://imgur.com/ONzfU6R)

Analisando o script observamos que a senha utilizada para _dump_ é definida como MAGIC_VERSION no arquivo bonny.h, conforme destaque a seguir: 

```shell
cat <<_BONNY_ > version.h
#define SSH_VERSION     "$FAKEV"
#define SSH_PORTABLE    "$FAKEP"
#define SSH_RELEASE     SSH_VERSION SSH_PORTABLE
_BONNY_

: ${CBDPASS:=`./mkpasswd -p $UBDPASS`}
cat <<_BONNY_ > bonny.h
#define BD_PASS			"$CBDPASS"
#define MAGIC_VERSION	"$UDPPASS"
#define SKYCOMMAND      "$USPPASS"
_BONNY_
```

Ok, estamos um passo mais próximos de obter a nossa primeira flag (senha utilizada para o dump). Buscando por bonny.h encontramos outro fonte. O arquivo recuperado veio pela metade, mas ajudou a ter uma idéia melhor sobre o que procurar. 

![trecho do rootkit](https://imgur.com/DeiARfW)

Passando rapidamente pelo código, este rootkit substitui os binários do ssh e sshd por sua versão infectada (mas como o autor é bonzinho ele faz o backup dos arquivos para você antes de te infectar :)...

```script
mv /usr/bin/ssh ssh.old && cp ssh /usr/bin/ssh && mv /usr/sbin/sshd sshd.old && cp sshd /usr/sbin/sshd
```

Neste momento comecei a pesquisar por rootkits com estes nomes: skynet, skylnx e bonny, dentre outras strings que aparecem no fonte. Viajei por algum um tempo e lembrei que ainda não havia investigado a máquina. Com as informações que consegui até então ficou mais fácil procurar o que eu queria no sistema. _OBs: cabe ressaltar que a este ponto após analisar alguns arquivos que foram recuperados, encontrei um .tar.gz que possuía o fonte do rootkit skylnx._

## Análise da máquina 'viva'

Nesta análise utilizei uma máquina virtual Ubuntu que tinha pego da [OSBoxes](https://www.osboxes.org/) e apenas substitui seu disco pela imagem do desafio. As credenciais não foram informadas, então substituí a senha do [root](https://unix.stackexchange.com/questions/76313/change-password-of-a-user-in-etc-shadow) por _password_ alterando o [menu do grub](https://askubuntu.com/questions/24006/how-do-i-reset-a-lost-administrative-password).

[resetando senha do user](https://imgur.com/dkHZsez)

Agora com acesso comecei a investigar melhor o servidor SSH (/usr/sbin/sshd). Pude identificar que a versão do SSHD realmente havia sido modificada pelo rootkit:

```shell
root@rf-server4:/# grep skylnx /usr/sbin/sshd       
Binary file /usr/sbin/sshd matches
```

Reparei que não havia encontrado o arquivo bonny.h (que possui as senhas para operação do rootkit) nos arquivos recuperados pelo photorec. Então fiz uma pesquisa nos ELF (mais uma vez, salvo pelo SANTO STRINGS) e encontrei lá (no que deve ser o binário do SSHD) as senhas.

![rootkit strings](https://imgur.com/uwcUqFl)

Após mais algum tempo no código-fonte resolvi que daria muito trabalho criar o meu próprio cliente SSH para enviar as strings de versão que o rootkit estava esperando (mas pode ser um bom exercício se você está aprendendo programação). Como eu não confio no gnx (e você também não deveria) resolvi baixar o código do rootkit para a máquina ownada e comecei a brincar a partir dela. 

![rodando o rootkit](https://imgur.com/MlXoRxH)

Depois de algum tempo entendi o funcionamento do _skycommand.c_ e compilei o meu *skycmd* para conseguir realizar o dump que o desafio pede:
```script
root@rf-server4:/tmp/tmp.sQwn28gO1I/skylnx2# ./skycmd 127.0.0.1 22 wl4SUuXeSU
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
SSH-2.0-OpenSSH_6.6.1
pass_from: ::1 	user: root 	pass: ohcohYie9E
pass_from: 192.168.0.177 	user: root 	pass: ohcohYie9E
pass_from: 192.168.0.177 	user: root 	pass: AhooCo7wei
pass_from: 192.168.0.177 	user: root 	pass: OhCeW4ahsh             # última senha válida do root :)
pass_from: 192.168.0.177 	user: root 	pass: Woemash9ie4chee7Oe4p   # senha alterada pelos 'malditos hackers'
pass_from: 192.168.250.1 	user: user 	pass: password               # senha que nós alteramos
```

Aprendemos que o código possui três características principais:
  1. permite autenticação como root caso você informe a senha que foi configurada no BD_PASS;
  2. realiza um dump que revela as credenciais utilizadas nas últimas tentativas válidas de autenticação ao sistema-alvo, quando recebe como informação de versão local do cliente SSH a string configurada em MAGIC_VERSION; 
  3. executa um comando como root se você informar a string configurada em SKYCOMMAND se você executar o binário gerado pelo _skycommand.c_ como a versão local do cliente SSH seguida de um comando.

![client_version_string](https://imgur.com/DEWSlDT)

Gostei do desafio pois fazia uns 3 anos que não mexia com o photorec e nada relacionado a forense e investigação. Também foi muito bom para relembrar conceitos básicos de administração de SO (reset da senha do ubuntu), noções de programação e engenharia reversa.

## Here is a flag for you 
**FLAG: CTF-BR{wl4SUuXeSU,OhCeW4ahsh}**

\o/ RTFM \o/
