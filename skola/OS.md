**1.350,00 RSD**# Vezbe

## Cas 1

- Ceste greske

1. **NEINICIJALIZOVANI POKAZIVACI**

Neinicijalizovani pokazivaci, u njima se nalazi djubre iz memorije. Vrlo cesta mogucnost segmentation faulta. Derefenciranje null pointera je segfault. Niz od 100 charova moze i dalje da ide dokle god isto kao i `char *s` samo sto ce nakon prekoracenja uvek doci do segfaulta.

Printf ide do terminirajuce nule uvek, a ako je posle niza nula radi printf, a ako je posle niza neki ogroman broj onda nece naci nulu, za nizove charova poslednji mora da bude terminirajuca nula. Funkcije iz zaglavlja string.h uvek vode racuna o terminirajucim nulama.

Standardna C biblioteka je iznad kernela.

Rekastovanje pokazivaca struktura nije ispravna stvar`

Makroio su mnogo efikasniji za male stvari od funkcija


## Cas 2

## Cas 3

![[Pasted image 20231030152556.png]]
Flagovi za fajlove

