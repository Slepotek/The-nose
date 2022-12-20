#include<stdio.h>
#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>
#include<linux/if_packet.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>    // for ethernet header
#include<netinet/ip.h>		    // for ip header
#include<netinet/udp.h>		    // for udp header
#include<netinet/tcp.h>
#include<arpa/inet.h>           // to avoid warning at inet_ntoa
#include<linux/if_ether.h>
#include"netstructs.h"

#define PROTOKOL 3 //1 = TCP; 2 = UDP; 3 = ICMPv4; 4 = ICMPv6; 0 = Bez protokolu warstwy wyzszej
#define IPVER 4    //4 = IPv4; 6 = IPv6; 0 = Bez protokolu routingu
#define PHYSIC 1   //1 = IP; 2 = ARP
#define STRUKTURY 1//1 = kozystamy z utworzonych struktur; 0 = kozystamy wyswietlania bitowego
#define LISTA 0    //1 = aby korzystac z listy na ocene 4.5 0 = lista wylaczona

struct sockaddr saddr; //struktura adresu gniazda generyczny - czyli ten przed IP
struct sockaddr_in source, dest; //struktura adresu gniazda Internetowego

//definicja wlasnych struktur z pliku netstructs.h
struct iphead *ipheader;
struct ethhead *ethheader;
struct tcphead *tcpheader;
struct udphead *updheader;
struct icmphead *icmpheader;
struct ipv6head *ipv6header;

//funkcje listy wiazanej
void wstaw(Element_bufora **wsk_nagl, int *wsk_listy); //funkcja do dodawania elementu do listy
void print(Element_bufora *element); //funkcja do wyświetlania elementów listy
void usun(Element_bufora **header, int pozycja); //funkcja do usuwania elementów listy

//funkcje sluzace do wyswietlania naglowkow poszczegolnych protokolow za pomoca
//przypisanych do nich struktur wlasnych
void PrintIpHddr(unsigned char *data, int Size);
void PrintEthHddr(unsigned char *data, int Size);
void PrintICMPHddr(unsigned char *data, int Size);
void PrintIPV6Hddr(unsigned char *data, int Size);
void PrintUdpHddr(unsigned char *data, int Size);
void PrintTcpHddr(unsigned char *data, int Size);

int main() {
#if LISTA == 1
	int *wsk_listy = malloc(sizeof(int)); //inicjalizacja wskaznika listy - uzywany do zliczania elementow w liscie
	Element_bufora *lista = NULL; //inicjalizacja listy
	lista =(Element_bufora*)malloc(sizeof(Element_bufora));//zaalokowanie pamieci dla listy
	lista->poprzedni = NULL; //dalsza inicjalizacja
	lista->nastepny = NULL;
	lista->pierwszy = &lista;
	lista->buffer = (unsigned char*)malloc(65536);//zaalokowanie pamieci dla bufora ramki w liscie wiazanej
#endif
	int sock_r; //zmiena wskazujaca czy poprawnie utworzono gniazdo sieciowe
	int saddr_len; //zmienna przechowujaca wartosc dlugosci adresu gniazda
	int buflen; //dlugosc odczytanych przez gniazdo danych
	int i; //zmienna pomocnicza
	unsigned char *buffer = (unsigned char*) malloc(65536); //alokacja pamieci dla bufora ramki
	memset(buffer, 0, 65536); //wyzerowanie bufora

	printf("START .... \n");

	sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //otworzenie gniazda
	if (sock_r < 0) //wartosc mniejsza od 1 wskazuje ze gniazdo nie otworzylo sie poprawnie
			{
		printf("BLAD PODCZAS OTWIERANIA GNIAZDA\n");
		return -1;
	}

	while (1) {
		saddr_len = sizeof saddr; //ustawienie dlugosci adresu
		buflen =
				recvfrom(sock_r, buffer, 65536, 0, &saddr,
						(socklen_t*) &saddr_len); //odbior danych przez gniazdo i wpisanie danych do bufora
#if LISTA == 1
		buflen=recvfrom(sock_r,lista->buffer,65536,0,&saddr,(socklen_t *)&saddr_len);//odbior danych przez gniazdo i wpisanie danych do listy wiazanej
		wstaw(&lista, wsk_listy);//utworz nowy, pusty element listy wiazanej (do poprzedniego elementu juz wpisalismy dane)
	    if(wsk_listy == 20)//jezeli wskaznik listy osiagnie wartosc 20
	    {
	    	print(lista);//zacznij wyswietlac liste i zawarte w niej elementy (zwrocic uwage na poprawna sekwencje Print'ow do zadanego stacka protokolow
	    }
	    while (lista != NULL)//procedura do usuwania elementow listy po ich odczytaniu
	     {
	    	Element_bufora *temp = lista; //utworz tymczasowy wskaznik na pierwszy element z listy
	        lista = lista->nastepny;//przejdz do nastepnego elementu w liscie
	        free(temp);//usun dane elementu na ktory wskazywal wskaznik tymczasowy
	     }
#endif
		if (buflen < 0) //jezeli wielkosc bufora jest mniejsza niz 0
				{
			printf("BLAD ODBIORU\n"); //blad w odbieraniu ramki przez gniazdo
			return -1;
		} else {
			printf("\nOdebrano ramke Ethernet o rozmiarze: %d [B]\n", buflen);
			struct ethhead *ethheader = (struct ethhead*) buffer; //utworz structure do przechowania naglowka ethernetowego
			printf("Typ protokolu w naglowku Ethernet ");
			switch (ntohs(ethheader->typ)) //sprawdz jaki typ protokolu warstwy wyrzszej byl przekazany w ramche ethernet (funkcja nthos - odwraca bity, bo jak wiemy po przeslaniu przez gniazdo zmieniaja kolejnosc)
			{
			case 2048: // numery przypisane do poszczegolnych protokolow
				puts("IPV4");
				break;
			case 2054:
				puts("ARP");
				break;
			case 34525:
				puts("IPV6");
				break;
			default:
				puts("Niezidentyfikowany protokol");
				break;
			}
#if PHYSIC == 1 //IP
#if IPVER == 4 //IPv4
#if STRUKTURY == 0
			//numery przy zmiennej buffer oznaczaja kolejne bajty odczytywane z ramki
				printf("\n");
				printf("Wersja protokolu i dlugosc naglowka ");
				printf("%.2x ", buffer[14]);
				printf("\n");
				printf("QoS ");
				printf("%.2x ", buffer[15]);
				printf("\n");
				printf("Calkowita dlugosc ramki ");
				for (i = 16; i <= 17; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Identyfikator ");
				for (i = 18; i <= 19; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Flagi i offset fragmentacji ");
				for (i = 20; i <= 21; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Czas zycia pakietu ");
				printf("%.2x ", buffer[22]);
				printf("\n");
				printf("Protokol ");
				printf("%.2x ", buffer[23]);
				printf("\n");
				printf("Suma kontrolna ");
				for (i = 24; i <= 25; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Zrodlo ");
				for (i = 26; i <= 29; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Adresat ");
				for (i = 30; i <= 33; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Opcje IP + wypelnienie ");
				for (i = 34; i <= 39; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
			#endif
#if STRUKTURY == 1
			PrintIpHddr(buffer + 14, sizeof(buffer)); //funkcja wpisuje dane do struktury przypisanej do protokolu i wyswietla ich zawartosc na wyjsciu standardowym (patrz. definicje funkcji pod programem)
#endif
			//*************************************
#if PROTOKOL == 0 //bez protokolu
				printf("Dane:\n");
				int j = 0;
				for (i = 40; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif //bez protokolu
			//**********************************
#if PROTOKOL == 1 //TCP
				#if STRUKTURY == 0
				printf("Protokol TCP:\n");
				printf("Port zrodla ");
				for (i = 40; i <= 41; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Port adresata ");
				for (i = 42; i <= 43; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Numer sekwencji ");
				for (i = 44; i <= 47; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Flaga ACK ");
				for (i = 48; i <= 51; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Offset oraz flagi protokolu TCP ");
				for (i = 52; i <= 53; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Rozmiar okna ");
				for (i = 54; i <= 55; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("CRC ");
				for (i = 56; i <= 57; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Wskaznik pilnosci ");
				for (i = 58; i <= 59; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Reszta danych:\n");
				int j = 0;
				for (i = 60; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
				#if STRUKTURY == 1
					PrintTcpHddr(buffer+40, sizeof(buffer));//jak wyzej
				#endif
				#endif// TCP
			//**********************************
#if PROTOKOL == 2 //UDP
				#if STRUKTURY == 0
				printf("Protokol UDP:\n");
				printf("Port zrodlowy ");
				for (i = 40; i <= 41; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Port docelowy ");
				for (i = 42; i <= 43; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Dlugosc danych ");
				for (i = 44; i <= 45; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("CRC ");
				for (i = 46; i <= 47; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Dane:\n");
				int j = 0;
				for (i = 48; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
				#if STRUKTURY == 1
					PrintUdpHddr(buffer+40, sizeof(buffer));//jak wyzej
				#endif
				#endif//UDP
			//**********************************
#if PROTOKOL == 3 //ICMPv4 (ping)
#if STRUKTURY == 0
				printf("Protokol ICMP:\n");
				printf("Typ ");
				printf("%.2x ", buffer[40]);
				printf("\n");
				printf("Kod ");
				printf("%.2x ", buffer[41]);//tutaj w przypadku pinga powinno byc 00 ale na moim srodowisku pojawia sie 01, nie wiem jaka jest tego przyczyna moze maslanka albo krygier wyjasnia
				printf("\n");
				printf("CRC ");
				printf("%.2x %.2x", buffer[42], buffer[43]);
				printf("\n");
				printf("Dane:\n");
				int j = 0;
				for (i = 44; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
#if STRUKTURY == 1
			PrintICMPHddr(buffer + 40, sizeof(buffer)); //jak wyzej
#endif
#endif //ICMPv4
			//**********************************
#endif //IPv4
#if IPVER == 6 //IPv6
	#if STRUKTURY == 0
				printf("\n");
				printf("Wersja protokolu -> ");
				printf("%.2x ", buffer[14]&0xf0);//tutaj uzywamy maskowania bitow, czyli z formy 1101 0110 zostawiamy tylko 1101 0000 funkcja and dodalismy sekwencje 1111 0000
				printf("\n");
				printf("Klasa ruchu ");
				unsigned char tc = buffer[14]&0x0f;//tutaj to samo co wyzej tylko odwrocone zamiast 1111 0000 jest 0000 1111
				tc = tc << 4; //operacja bitowa, przesowamy bity o 4 w lewo czyli np. z 0000 0100 robimy 0100 0000
				unsigned char tcb = buffer[15]&0xf0;
				tc = tc & tcb;
				printf("%.2x ", tc);
				printf("\n");
				printf("Etykieta przeplywu ramki ");
				unsigned char fl = buffer[15]&0x0f;
				printf("%.2x %.2x %.2x", fl, buffer[16], buffer[17]);
				printf("\n");
				printf("Dlugosc ramki ");
				for (i = 18; i <= 19; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Nastepny naglowek ");
				printf("%.2x ", buffer[20]);
				printf("\n");
				printf("Limit skokow ");
				printf("%.2x ", buffer[21]);
				printf("\n");
				printf("Adres zrodla ");
				for (i = 22; i <= 37; i++)
				{
					printf("%.2x", buffer[i]);
					if((i%2))
					{
						if(i!=37)
							printf(":");
					}
				}
				printf("\n");
				printf("Adres celu ");
				for (i = 38; i <= 53; i++)
				{
					printf("%.2x", buffer[i]);
					if((i%2))
					{
						if(i!=53)
							printf(":");
					}
				}
				printf("\n");
				//*************************************
				#if PROTOKOL == 0 //bez protokolu
				printf("Dane:\n");
				int j = 0;
				for (i = 54; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif //bez protokolu
	#endif
	#if STRUKTURY == 1
				PrintIPV6Hddr(buffer+14, sizeof(buffer));//jak wyzej
	#endif
				//**********************************
				#if PROTOKOL == 1 //TCP
#if STRUKTURY == 0
				printf("Protokol TCP:\n");
				printf("Port zrodla ");
				for (i = 54; i <= 55; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Port adresata ");
				for (i = 56; i <= 57; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Numer sekwencji ");
				for (i = 58; i <= 61; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Flaga ACK ");
				for (i = 62; i <= 65; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Offset oraz flagi protokolu TCP ");
				for (i = 66; i <= 67; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Rozmiar okna ");
				for (i = 68; i <= 69; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("CRC ");
				for (i = 70; i <= 73; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Wskaznik pilnosci ");
				for (i = 74; i <= 75; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Reszta danych:\n");
				int j = 0;
				for (i = 76; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
				#if STRUKTURY == 1
				PrintTcpHddr(buffer+54, sizeof(buffer));
				#endif
				#endif// TCP
				//**********************************
				#if PROTOKOL == 2 //UDP
				#if STRUKTURY == 0
				printf("Protokol UDP:\n");
				printf("Port zrodlowy ");
				for (i = 54; i <= 55; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Port docelowy ");
				for (i = 56; i <= 57; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Dlugosc danych ");
				for (i = 58; i <= 59; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("CRC ");
				for (i = 60; i <= 61; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Dane:\n");
				int j = 0;
				for (i = 62; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
				#if STRUKTURY == 1
				PrintUdpHddr(buffer+54, sizeof(buffer));//jak wyzej
				#endif
				#endif//UDP
				//**********************************
				#if PROTOKOL == 4 //ICMPv6
				#if STRUKTURY == 0
				printf("PAKIET ICMPv6: \n");
				printf("   Typ: %.2x\n", buffer[54]);
				printf("   Kod: %.2x\n", buffer[55]);
				printf("   CRC: %.2x %.2x\n", buffer[56], buffer[57]);
				printf("Dane:\n");
				int j = 0;
				for (i = 58; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");
				#endif
				#if STRUKTURY == 1
				PrintICMPHddr(buffer+54, sizeof(buffer));//jak wyzej - ICMP dla IPv6 jest taki sam jak w IPv4 tylko jego pozycja w ramce jest inna
				#endif
				#endif//ICMPv6
	#endif //IPVER == IPv6
#endif //PHYSIC == IP
#if PHYSIC == 2
				printf("\n");
				printf("Typ warstwy fizycznej ");
				for (i = 14; i <= 15; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Typ protokolu wyzszej warstwy ");
				for (i = 14; i <= 15; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Dlugosc adresu sprzetowego ");
				printf("%.2x ", buffer[16]);
				printf("\n");
				printf("Dlugosc protokolu wyzszej warstwy ");
				printf("%.2x ", buffer[17]);
				printf("\n");
				printf("Typ warstwy fizycznej ");
				for (i = 18; i <= 19; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Adres sprzetowy zrodla ");
				for (i = 20; i <= 23; i++)
				{
					printf("%.2x ", buffer[i]);
				}
				printf("\n");
				printf("Reszta danych:\n");//ze wzgledu na mozliwosc roznego rozmiaru, dlasze pola wyswietlane sa jako calosc
				int j = 0;
				for (i = 58; i < buflen; i++)
				{
					if(j == 10)
					{
						printf("\n");
						j = 0;
					}
					printf("%.2x ", buffer[i]);
					j++;
				}
				printf("\n");

#endif
		}

	}
	close(sock_r); // zamkniecie gniazda sieciowego
	printf("KONIEC\n");

}

void PrintIpHddr(unsigned char *data, int Size) { //funkcja do wyswietlenia naglowka IP + wpisanie danych do wlasnej struktury z naglowkiem
	unsigned short iphdrlen;//zmienna z dlugoscia naglowka (ilosc danych w naglowku)
	struct iphead *iph = (struct iphead*) data;//inicjalizacja wlasnej struktury naglowka ip (po wiecej info patrz netstructs.h
	iphdrlen = iph->dlugosc * 4;//wylicz dlugosc danych naglowka
	memset(&source, 0, sizeof(source));//wyzerowanie struktury adresu zrodla (adresu czyli np. 127.0.0.1)
	source.sin_addr.s_addr = iph->zrodlo;// wpisz do struktury zrodla odebrany w ramce adres IP zrodla
	memset(&dest, 0, sizeof(dest));//jak wyzej tylko dla adresu przeznaczenia
	dest.sin_addr.s_addr = iph->destyn;// wpisz do struktury adresu przeznaczenia adres odebrany w ramce IP
	printf("\n");
	printf("IP Header\n");
	//i po kolei wypisujemy kolejne elementy ze struktury Przypominam funkcja ntohs odwraca bity, zeby system je prawidlowo odebral po przeslaniu, nie wszystkie pola trzeba w ten sposob traktowac, tylko te ktore nie sa wyswietlane w hexie
	printf(" |-IP wersja: %d\n", (unsigned int) iph->wersja);
	printf(" |-IP dlugosc naglowka : %d bajtow\n",
			((unsigned int) (iph->dlugosc)) * 4);
	printf(" |-Typ uslugi : %d\n", (unsigned int) iph->uslug_ecn);
	printf(" |-IP calkowita dlugosc wiadomosci : %d bajtow\n",
			ntohs(iph->calk_dlug));
	printf(" |-Identification : %d\n", ntohs(iph->identy));
	printf(" |-TTL : %d\n", (unsigned int) iph->czas_zy);
	printf(" |-Protocol : %d\n", (unsigned int) iph->protok);
	printf(" |-Checksum : %d\n", ntohs(iph->suma_kontr));
	printf(" |-Source IP: %s\n", inet_ntoa(source.sin_addr));//tutaj funkcja inet_ntoa to wbudowana funkcja biblioteki bodaj netinet arpa oraz socket, sluzy do wyswietlenia adresu w postaci jaka wszyscy znamy czyli np. 127.0.0.1
	printf(" |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
	printf("\n");
}

void PrintEthHddr(unsigned char *data, int Size) { //funkcja do wyswietlania naglowka ethernetowego
	struct ethhead *ethheader = (struct ethhead*) data; //wlasna struktura naglowka ethernetowego (po wiecej info patrz netstructs.h)
	printf("\n");
	printf("Ethernet Header\n");
	printf(" |-Adresat: ");
	for (int i = 0; i < 6; i++) {
		printf(" %.2x ", (unsigned int) ethheader->adresat[i]);
	}
	printf("\n");
	printf(" |-Zrodlo: ");
	for (int i = 0; i < 6; i++) {
		printf(" %.2x ", (unsigned int) ethheader->zrodlo[i]);
	}
	printf("\n");
	printf(" |-Typ : %d\n", (unsigned short) ethheader->typ);
	printf("\n");
}

void PrintTcpHddr(unsigned char *data, int Size) {//funkcja do wyswietlenia naglowka tcp, uzupelnia rowniez strukture
	struct tcphead *tcpheader = (struct tcphead*) data;// wlasna struktura naglowka tcp (po wiecej info patrz netstruct.h)
	printf("\n");
	printf("TCP Header\n");
	printf(" |-TCP zrodlo: %d\n", ntohs(tcpheader->zrodlo));
	printf(" |-TCP adresat : %d\n", ntohs(tcpheader->adresat));
	printf(" |-TCP nr sekwencji : %d\n", ntohs(tcpheader->nr_sekw));
	printf(" |-TCP numer ACK : %d\n", ntohs(tcpheader->ack));
	printf(" |-TCP rozmiar okna : %d\n", ntohs(tcpheader->rozm_okn));
	printf(" |-TCP suma kontrolna : %d\n", ntohs(tcpheader->suma_kontr));
	printf(" |-TCP wskanik pilnosci : %d\n", ntohs(tcpheader->wsk_piln));
	printf("\n");
}

void PrintUdpHddr(unsigned char *data, int Size) {//funkcja do wyswietlania naglowka udp, usupelnia rowniez strukture
	struct udphead *udpheader = (struct udphead*) data;//wlasna struktura naglowka udp (po wiecej info patrz netstruct.h)
	printf("\n");
	printf("UDP Header\n");
	printf(" |-UDP zrodlo: %d\n", ntohs(udpheader->zrodlo));
	printf(" |-UDP adresat : %d\n", ntohs(udpheader->adresat));
	printf(" |-UDP dlugosc danych : %d\n", ntohs(udpheader->dlugosc));
	printf(" |-UDP suma kontrolna : %d\n", ntohs(udpheader->suma_kontr));
	printf("\n");
}

void PrintIPV6Hddr(unsigned char *data, int Size) {//funkcja do wyswietlania naglowka IPv6, uzupelnia rowniez strukture
	struct ipv6head *ipv6header = (struct ipv6head*) data;//wlasna struktura naglowka Ipv6 (po wiecej info patrz plik netstructs.h)
	printf("\n");
	printf("IPV6 Header\n");
	printf(" |-IPV6 wersja: %.2x\n", (unsigned int) ipv6header->wersja);
	printf(" |-IPV6 klasa ruchu: %.2x\n", ipv6header->klasaRuchu);
	printf(" |-IPV6 etykieta przeplywu: %.2x\n",
			ntohs(ipv6header->etykieta_przep));
	printf(" |-IPV6 rozmiar danych : %d\n", ntohs(ipv6header->rozmiar_danych));
	printf(" |-IPV6 etykieta nastepnego naglowka : %d\n",
			(unsigned int) ipv6header->nastep_nagl);
	printf(" |-IPV6 limit przeskokow : %d\n",
			(unsigned int) ipv6header->limit_przesk);
	printf(" |-IPV6 adres zrodla ");
	for (int i = 0; i < 8; i++) {
		printf("%d", ntohs(ipv6header->zrodlo[i]));
		if (i != 7)
			printf(":");
	}
	printf("\n");
	printf(" |-IPV6 adres docelowy ");
	for (int i = 0; i < 8; i++) {
		printf("%d", ntohs(ipv6header->zrodlo[i]));
		if (i != 7)
			printf(":");
	}
	printf("\n");
}

void PrintICMPHddr(unsigned char *data, int Size) {//funkcja do wyswietlania naglowka ICMP
	struct icmphead *icmpheader = (struct icmphead*) data;// wlasna struktura do przechowywania naglowka ICMP
	printf("\n");
	printf("ICMP Header\n");
	printf(" |-ICMP typ: %d\n", icmpheader->typ);
	printf(" |-ICMP kod : %d\n", icmpheader->kod);
	printf(" |-ICMP suma_kontr : %x\n", icmpheader->suma_kontr);
	printf("\n");
}


//FUNKCJE LISTY WIAZANEJ
//generalnie zalozenie jest takie ze w strukturach listy przechowujemy bufor z danymi
//nie inne struktury w ten sposob jest dla was prosciej zdefiniowac to co faktycznie bedzie
//chcial prowadzacy
void wstaw(Element_bufora **wsk_nagl, int *wsk_listy) {
	Element_bufora *nowy_wpis = (Element_bufora*) malloc(
			sizeof(Element_bufora)); //zajmij pamięć dla nowego elementu listy

	nowy_wpis->buffer = (unsigned char*) malloc(65536);
	nowy_wpis->nastepny = (*wsk_nagl); //wpisz pod adres elementu następnego pierwszy element z listy
	nowy_wpis->poprzedni = NULL; //adres poprzedniego elementu w nowym elemencie wyzeruj (elementy dodawane są na początek listy)

	if ((*wsk_nagl) != NULL) //jeżeli pierwszy element nie jest pusty (trzeba sprqawdzić, żeby nie pojawił się błąd)
	{
		(*wsk_nagl)->poprzedni = nowy_wpis; //wpisz w pole adresu elementu poprzedniego, adres poprzednio pierwszego elementu
	}
	(*wsk_nagl) = nowy_wpis; //przypisz pod adres pierwszego elementu(header) nowy element listy
	wsk_listy++;
}
void print(Element_bufora *element) {
	printf("\n Elementy listy \n");
	while (element != NULL) //jeżeli pod adresem "element" nie ma pustej pamięci
	{
		//UWAGA*************************************************************************
		//zeby dzialalo trzeba wstawic odpowiednia strukture do tego co zadal prowadzacy
		//np
		PrintIpHddr(element->buffer + 14, sizeof(element));
		PrintTcpHddr(element->buffer + 40, sizeof(element));
		//UWAGA*************************************************************************
		element = element->nastepny; //przenieś adres do następnego elementu z listy
	}
}

void usun(Element_bufora **header, int pozycja) {
	Element_bufora *temp; //tymczasowa zmienna, używana żeby zapewnić spójność listy
	Element_bufora *pTemp; //tak samo jak wyżej
	temp = *header; //przypisz do tymczasowej zmiennej adres pierwszego elementu listy
	pTemp = *header; //to samo co wyżej (ale później przechowuje element poprzedzający temp)
	for (int i = 0; i < pozycja; i++) { //przechodź po kolejnych elementach listy aż do zadanego elementu
		if (i == 0 && pozycja == 1) { //jeżeli wskazany element to pierwszy element z listy
			*header = (*header)->nastepny; //pod adres pierwszego elementu przypisz adres następnego elementu z pierwszego elementu
			free(temp); // uwlonij pamięć zaalokowaną dla tymczasowych zmiennych
		} else {
			if (i == pozycja - 1 && temp) { //jeżeli wskazywana pozycja jest równa pozycji elementu - 1 i temp != NULL
				pTemp->nastepny = temp->nastepny; //przypisz następny element elementu temp jako następny element elementu poprzedzającego element temp
				free(temp);
			} else { //jeżeli iterator nie dotarł jeszcze do wymaganej pozycji
				pTemp = temp; //przepisz element ze zmiennej temp do zmienej pTemp

				if (pTemp == NULL) //sprawdź czy nie przekroczono zakresu listy
				{
					break; //jeżeli przekroczono - przerwij wykonywanie procedury
				}
				temp = temp->nastepny; // zmień adres zmiennej temp na kolejny element listy
				//teraz w zmiennych pomocniczych przechowywany jest
				/*temp - bierzący element w iteracji
				 pTemp - element poprzedzający element temp*/
			}
		}
	}
}
