#ifndef NETSTRUCTS_H
#define NETSTRUCTS_H

//definicja struktury listy wiazanej
typedef struct {
    unsigned char *buffer;
	struct Element_bufora *nastepny;
	struct Element_bufora *poprzedni;
	struct Element_bufora *pierwszy;
}Element_bufora;

//definicja struktury naglowka ip
struct iphead
{
	unsigned int dlugosc:4;
	unsigned int wersja:4;
	unsigned char uslug_ecn;
	unsigned short calk_dlug;
	unsigned short identy;
	unsigned short frag_flagi;
	unsigned char czas_zy;
	unsigned char protok;
	unsigned short suma_kontr;
	unsigned int zrodlo;
	unsigned int destyn;
};
//deklaracja struktury naglowka ethernet
struct ethhead
{
	unsigned char adresat[6];
	unsigned char zrodlo[6];
	unsigned short typ;
};
//deklaracja naglowka struktury tcp
struct tcphead
{
	unsigned short zrodlo;
	unsigned short adresat;
	unsigned int nr_sekw;
	unsigned int ack;
	unsigned short rozm_okn;
	unsigned short suma_kontr;
	unsigned short wsk_piln;
};
//deklaracja struktury naglowka udp
struct udphead
{
	unsigned short zrodlo;
	unsigned short adresat;
	unsigned short dlugosc;
	unsigned short suma_kontr;
};
//deklaracja struktury naglowka ipv6
struct ipv6head
{
	unsigned char wersja;
	unsigned char klasaRuchu:4;
	unsigned int etykieta_przep:20;
	unsigned short rozmiar_danych;
	unsigned char nastep_nagl;
	unsigned char limit_przesk;
	unsigned short zrodlo[8];
	unsigned short adresat[8];
};
//deklaracja struktury naglowka icmphead
struct icmphead
{
	unsigned char typ;
	unsigned char kod;
	unsigned short suma_kontr;
};

#endif
