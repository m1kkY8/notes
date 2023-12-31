---
id: OS Vezbe
aliases:
  - 1. cas
tags: []
---


--- 
# 1. cas

## Podsecanje iz P1 i P2, i ceste greske na ispitima.

- Neinicijalizovani pokazivac
- Stringovi bez terminirajuce nule kada se rucno radi sa stringovima
	- Rucno postavljanje nule na kraj stringa je obavezno da funkcije za ispis ne bi citale smece iz memorije
	- Svaka funkcija iz ```string.h``` automatski stavlja terminirajucu nulu na kraj stringa
- Definisanje makroa za proveru greska koji ce biti cesto koriscenj tokom kursa.

```C
define check_error(cond, msg)\
	do{\
		if(!(cond)){\
			perror(msg);\
			exit(1);\
		}\
	} while(0)
```

- Ovaj makro se koristi tako sto se kao cond stavi uslov koji ne sme da bude true, na primer kod rada sa File Descriptorima kada proveravamo `check_error(fd != -1)`, u slucaju da je fd -1 mi izbacujemo gresku. Takodje je jako bitno da koristimo `errno.h` zaglavlje koje nam omogucava detaljniji uvid u to sta je tacno greska.

>[!warning]+ OBAVEZNO
> **Pokazivace uvek inicijalizovati na NULL**
> **Uvek nakon alokacije proveriti da li je alokacija uspesna**
> **Uvek zatvoriti otvorene fajlove i fajl dekriptore**
> **Uvek osloboditi alociranu memoriju nakon sto ona prestane da se koristi**

> [!important] TLPI poglavlja
> - 3.4 Handling errors from Sys Calls

---
# 2. cas

## Dobijanje inforamcija o korisniku, grupi i fajlu

### Korisnici

- Na linux sistemima sve inforamcije o korisniku se cuvaju u /etc/passwd fajlu. Dok se informacije o grupi cuvaju u /etc/group

- Za informacije o korisniku moram da `#include <pwd.h` zaglavlje koje omogucava citanje /etc/passwd fajla, zbog sigurnosnih razloga korisnicke lozinke odnosno hashevi isti su smesteni u /etc/shadow koji zahteva specijalna prava pristupa da bi se otvorio i citao.

- Da bi dobili inforamcije o korisniku moramo da koristimo staticku strukturu  `struct passwd *userInfo`, userInfo je samo naziv strukture u ovom slucaju dok nju popunjavamo sistemskim pozivom `getpwnam()` koja kao argument prima niz karaktera koji je korisnicko ime u plain textu, postoji i druga funkcija koja vraca istu strkturu samo prima korisnicki id `uid_t`(User ID) i ona je `getpwuid()`.

- Za citanje celog /etc/passwd fajla koristimo funkcije `setpwent()` i `endpwent()` koje otvaraju i citaju i nakon toga zatvaraju /etc/passwd file.
- Trenutnog korisnika dobijamo tako sto pozovemo `getpwent()` i fajl citamo do kraj dok funkcija ne vrati `null`.

```c
setpwent();
struct passwd *user = NULL;

while((user = getpwent()) != NULL){

	print_users(user);
}
endpwent();
```
- Primer kako bi kod koji cita ceo fajl trebao da izgleda.
```C
void print_users(struct passwd* userInfo){

	fprintf(stdout, "\n");
	fprintf(stdout, "Username: %s\n", userInfo->pw_name);
	fprintf(stdout, "UID: %d\n", userInfo->pw_uid);
	fprintf(stdout, "GID: %d\n", userInfo->pw_gid);
	fprintf(stdout, "Home dir: %s\n", userInfo->pw_dir);
	fprintf(stdout, "Shell: %s\n", userInfo->pw_shell);
}
```
- Funkcija koja ispisuje korisnike u formatu koji je citljivi korisniku
### Grupe

- Grupe se obradjuju na isti nacin kao i korisnici samo sto se za gurpe koristi zaglavlje `grp.h`
- Informacije o grupi takodje mozemo dobijati na osnovu imena grupe i njenog ID-a koriscenjem funkcija `getgrnam()` i `getgrgid()` koje kao parametre primaju niz karaktera (ime grupe), odnosno `gid_t` sistemski tip koji je Group ID
- Podaci o grupi se cuvaju takodje u staticki alociranoj strukturi `sturct group* groupInfo` gde je `group` tip structure a groupInfo samo njen naziv.
- Ona se popunjava gore navedenim funkcijama.

- Kao kod `pwd.h` zaglavlja i `grp.h` omogucava citanje celog /etc/group fajla sa funckijama `setgrent()`, `getgrent()` i `endgrent()`

```c
setgrent();
struct group *currentGroup = NULL;

while((user = getgrent()) != NULL){

	print_group(currentGroup);
}
endgrent();
```
- Ovaj kod prolazi kroz ceo /etc/group fajl i ispisuje njegov sadrzaj onako kako mi odlucimo da ga formatiramo u fukciji `print_group()`
```C
void print_groups(struct group *grinfo){

	fprintf(stdout, "\n");
	fprintf(stdout, "%s\n", grinfo->gr_name);
	fprintf(stdout, "%d\n", grinfo->gr_gid);
	
	for(int i = 0; grinfo->gr_mem[i] != NULL; i++){
		fprintf(stdout, "%s\n", grinfo->gr_mem[i]);
	}

}
```
-  Ova fukcija za dati argument `*grinfo` ispisuje ime grupe, njen id i sve clanove koji su u toj grupi

### Fajlovi

- Na linux sistemima postoji 7 vrsta fajlova;
	1.  regularni fajlovi `-`
	2. direktorijumi `d`
	3. blok fajlovi, oni su obicno hardverske komponenete i nalaze su /dev direktorijumu `b`
	4. char fajlovi, ovo su ulazni i izlazni streamovi, terminal je jedan od char fajlova `c`
	5. pipe-ovi, ovo su fajlovi koji sluze za redirekciju izlaza jednog programa u ulaz drugog `p`
	6. simbolicki linkovi, oni sadrze stvarne putanje do nekog fajla `l`
	7. Socketi, koriste se za komunakciju izmedju aplikacija `s`

- Sve informacije o fajlu mozemo dobiti pomocu sistemskog poziva `stat()`, koji kao argumente prima putanju do fajla i pokazivac na strukturu `struct stat fileinfo` gde je fileinfo samo naziv.
- Iz stat funkcije mozemo da dobijemo informacije kao sto su prava pristupa u formatu `rwxrwxrwx` gde je r - read, w - write i x - executable. i redosled kojim su rasporedjeni oznacava prava korisnika, grupe i ostalih na sistemu

- Pre ovih 9 karaktera ide jedan karakter koji oznacava tip fajla (jedan od onih 7 sa pocetka).
- Struktura `stat` takodje sadrzi i informacije o velicini fajla, vremenu nastanka fajla, vremenu pristupa i vremenu modifikacije, `uid_t` korisnika koji je napravio fajl kao i `gid_t` kojoj taj korisnik pripada.

>[!important] TLPI poglavlja i materijali
> - 8.1 - 8.4, 15.1, 15.4-15.4.3
> - man 5 passwd i man 5 group

---
# 3. cas

## Sistemski pozivi za rad sa fajlovima

### Mkdir

- Poziv `mkdir` kreira direktorijum, kao argumente prima putanju na koji fajl treba biti kreiran i mod u kojem treba biti kreiran, odnosno `mode_t` promenljivu koja u sebi sadrzi prava pristupa u hexadecimalnom zapisu, na linuxu se prava pristupa oznacavaju trocifrenim hexadecimalnim brojem.

| User | Group | Other |
| ---- | ----- | ----- |
| rwx  | rwx   | rwx   |
| 111  | 101   | 101   |

- Ovo je ekvivalent kao da smo napsali 0755 za prava pristupa, ovo takodje znaci da korisnik moze da cita, pise i izvrsava dok svi ostali mogu samo da citaju i izvrasvaju

### Unlink i rmdir

- Brisanje fajlova se vrsi pozivom `unlink` koji uklanja fajl sa date putanje. Dok se za brisanje direktorijuma koristi `rmdir`, da bi `rmdir` uspesno radio direktorijum koji brisemo mora da bude prazan, kod neke implementacije mogli bi smo rekurzivno da prodjemo kroz zadati direktorijum pobrisemo sve fajlove sa `unlink` ili `rmdir` ako naidjemo na neki novi direktorijum i zatim obrisemo nas zadati direktorijum.

### Otvaranje fajlova

- Svaki otvoren fajl na sistemu ima svoj fajl desktriptor, on nam govori koji je fajl otvoren, sa kojim pravima pristupa i sa kojim flagovima smo otvorili taj fajl odnosno sta mozemo sa njim da radimo
- Za otvaranje fajlova koristimo funkciju `open` kojoj saljemo putanju do naseg fajla, flagove koji odredjuju kako se kreira fajl i prava pristupa.
![[Pasted image 20231117151739.png]]
- Ovo su flagovi sa kojima otvaramo fajlove.

- Nakon sto smo pozvali funkciju `open` ona vraca ceo broj int koji je nas file deskriptor koji nam omogucava da kasnije pisemo ili citamo otvoreni fajl.
- Fajl desktriptor ne sme da bude -1, u tom slucaju se dogodila greska pri otvaranju fajla.
- Na linux sistemima desktriptori pocinju od broja 3 posto su:
	1. 0 - STDIN - 0 je standardni ulaz
	2. 1 - STDOUT - 1 je standardni izlaz
	3. 2 - STDERR - 2 je standardni izlaz za greske

### Read i write

`read` poziv pokusava da cita podatke iz datog file deskriptora `read(int fd, void buf[.count], size_t count);`, `fd` je file desktriptor, `buf` je memorija u koju upisujemo procitanih `count` bajtova fajla, ako `read` vrati -1 znamo da citanje nije bilo uspesno.

```C
{
	int fd = open(argv[1], O_RDONLY);
	check_error(fd != -1, "open faild");

	char buf[BUFFER_SIZE];
	int readBytes = 0;

	while(readBytes = read(fd, buf, BUFFER_SIZE)){
		check_error(write(1, buf, readBytes) != -1, "write failed");
	}

	check_error(readBytes != -1, "read failed");

	close(fd);
}     
```
- U ovom kodu otvaramo fajl sa `O_RDONLY` flagom koji nam omugcava citanje fajla zatim alociramo niz karaktera `char buf[]` u koji cemo da smesatamo procitane podatke.
- Funkcija `read` vraca broj procitanih bajtova fajla i sve dok broj procitanih bajtova nije 0 nastavljamo da citamo, u slucaju da je `readBytes = -1` to znaci da je doslo do greske.
- Ova funkcija cita dati fajl i ispisuje ga na standardni izlaz, slicno kao progaram `cat` u linuxu.

### Kopiranje fajlova

```C
	int srcfd = open(argv[1], O_RDONLY);
	check_error(srcfd != -1, "srcfd");

	int destfd = open(argv[2], O_WRONLY | O_TRUNC | O_CREAT, 0644);
	check_error(destfd != -1, "destfd");

	char *buf = malloc(BUFF_SIZE);
	check_error(buf != NULL, "buffer");

	int readBytes = 0;

	while(readBytes = read(srcfd, buf, BUFF_SIZE)){
		check_error(write(destfd, buf, readBytes) != -1, "write");
	}

	check_error(readBytes != -1, "read");

	close(srcfd);
	close(destfd);
	free(buf);
```

- Kreiramo `int srcFd, int destFd`, koji su fajl dekriptori nasih fajlova `srcFd` je fajl koji kopiramo,  `destFd` je fajl u koji kopiramo, zatim inicalizujemo bafer za citanje i citamo sve dok `read` ne vrati 0.
- Problem kod ovog pristupa je sto mi ne zadrzvamo prava pristupa fajla koji kopiramo nakon sto se kopiranje zavrsi posto je `destFd` otvoren sa razlicitim pravima i on ce uvek imati prava 0644 ili `rw-r--r--` sto znaci da ce samo korisnik moci da cita i pise dok ce ostali moci samo da citaju.


> [!important] TLPI poglavlja
> - 4-4.7
> - 18.3 - unlink
> - 18.6 rmdir i mkdir
> - 15.2-15.2.1

--- 
# 4. cas

## Umask i promena prava pristupa

- Umask koristimo da bi dobili prava pristupa koja zelimo posto sistem ne dozvoljava kreiranje fajla sa `0777` pravima na primer. Sistem iz sigurnosnih razloga ne dozvoljava kreiranje fajlova koje mogu svi da citaju, pisu i izvrsavaju pa su default prava pristupa uglavnom `0775` ili `0664`

- Zeljena prava dobijamo kada zeljena prava `&` (and-ujemo) sa invertovanim umaskom.

- Za razliku od `chmod` , `umask` ne radi sa vec postojecim fajlovima vec samo omogucava kreiranje fajla sa zeljenim pravima.
- Komanda `chmod` menja prava datom fajlu `chmod [OPTION] mode ... FILE`

```C
int main(int argc, char** argv) {

    check_error(argc == 3, "./chmod file permissions");

    int prava = strtol(argv[2], NULL, 8);

        //kreira se fajl
    int fd = open(argv[1], O_CREAT, prava);
    check_error(fd != -1, "open");
    close(fd);

	//menjaju mu se prava pristupa
    check_error(chmod(argv[1], prava) != -1, "chmod");

    exit(EXIT_SUCCESS);
}
```
- Fukcija koja emulira sistemsku komandu `chmod` i menja mu prava pristupa, problem sa ovom funkcijom je taj sto mi ne bi smeli i ne bi trebali da otvaramo fajl ako zelimu da mu samo promenimo prava

```C
/* izdvajamo stara prava pristupa fajlu*/
    struct stat fileinfo;
    check_error(stat(argv[1], &fileinfo) != -1, "stat");
    mode_t current_mode = fileinfo.st_mode;

        /* dodajemo i oduzimamo trazena prava*/
    mode_t new_mode = (current_mode | S_IWGRP) & ~S_IROTH;

        /* menjaju mu se prava pristupa */
    check_error(chmod(argv[1], new_mode) != -1, "chmod");

    exit(EXIT_SUCCESS);
```
- Ova funckija ne otvara fajl ali mu menja prava pristupa tako sto ih prvo dobije iz `stat` strukture. Ova funkcija konkretno oduzima prava citanja za `other` a dodaje prava pisanja za `group` 

## Obilazak direktorijuma

- Obilazak direktorijuma mozemo uraditi na 2 nacina:
	1. tako sto cemo rucno napisati funkciju za rekurzivni prolaz kroz direktorijum
	2. koriscenjem `nftw` funkcije iz zaglavlja `<ftw.h>` (file tree walk)

- Rucna implementacija obilaska direktorijuma u dubinu
```C
void sizeOfDir(char* putanja, unsigned* psize) {
    /* citamo informacije o trenutnom fajlu */
    struct stat fInfo;
    check_error(lstat(putanja, &fInfo) != -1, "...");
    
    /* dodajemo velicinu fajla na tekuci zbir */
    *psize += fInfo.st_size;

    if (!S_ISDIR(fInfo.st_mode)) {
            /* prekidamo rekurziju */
		return;
    }

        /* ako je u pitanju dirketorijum, otvaramo ga */
    DIR* dir = opendir(putanja);
    check_error(dir != NULL, "...");

        /* u petlji citamo sadrzaj direktorijuma */
    struct dirent* dirEntry = NULL;
    errno = 0;
    while ((dirEntry = readdir(dir)) != NULL) {
 
        char* path = malloc(strlen(putanja) + strlen(dirEntry->d_name) + 2);
        check_error(path != NULL, "...");

                /* formiramo putanju na gore opisani nacin */
        strcpy(path, putanja);
        strcat(path, "/");
        strcat(path, dirEntry->d_name);

        if (!strcmp(dirEntry->d_name, ".") || !strcmp(dirEntry->d_name, "..")) {
            check_error(stat(path, &fInfo) != -1, "...");
            *psize += fInfo.st_size;

            free(path);
            errno = 0;
            continue;
            }
        sizeOfDir(path, psize);
        free(path);

        errno = 0;
        }

    check_error(errno != EBADF, "readdir");
        /* zatvaramo direktorijum */
    check_error(closedir(dir) != -1, "...");
}
```

-  Drugi nacin je samo koriscenjem funkcije `nftw` tako sto cemo joj posalti samo `const char *path*` putanju do fajla,  i pokazivac na funkciju kojom ce da obradi fajlove, `int f(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf`, broj otvorenih fajl deskriptora `int nopenfd` i `int statusflag`,

- `int f(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf` ova funkcija je zaduzena za obradjivanje fajla koji funkcija ntfw nadje;
	1. `const char *fpath`, je putanja koji `ntfw` prosledjuje ovoj funkciji
	2. `const struct stat *sb*`, je stat struktura pomocu koje mozemo da obradjujemo informacije o trenutnom fajlu koje je `nftw pronasao`
	3. `int typeflag` nam pomaze da brze utvrdimo tip fajla, na primer `FTF_F` znaci da je fajl na putanje `fpath` regularan fajl
	4. `ftwbuf` pruza funkciji uvid u struktur `FTW` koja sadrzi dve promenljive, `int base` i `int level`, `base` oznacava koliko daleko smo odmakli od pocetka nase putanje a `level` koliko smo duboko, 

- Implementacija prolaza sa `nftw`
```C
int days = 0;

int filterByTime(const char* fpath, const struct stat* sb, int typeflag, struct FTW* ftwbuf) {

    time_t now = time(NULL);
	time_t diffInSec = now - sb->st_mtime;
	
	if (diffInSec/DAY_IN_SEC < days)
        printf("%-80s\n", fpath);

    return 0;
}

int main(int argc, char** argv) {
    check_error(argc == 3, "./filterExt path days");

        /* prebacivanje stringa u broj */
    days = atoi(argv[2]);

        /* provera da li se radi o direktorijumu */
    struct stat fInfo;
    check_error(stat(argv[1], &fInfo) != -1, "stat failed");
    check_error(S_ISDIR(fInfo.st_mode), "not a dir");

        /* obilazak direktorijuma pomocu ugradjene funkcije */
    check_error(nftw(argv[1], filterByTime, 50, 0) != -1, "nftw failed");

    exit(EXIT_SUCCESS);
}
```
- Ova funkcija ispisjue sve fajlove koji su modifikovani u poslenjih `days` dana

>[!important] TLPI poglavlja
> 15.4.6, 15.4.7
> 18.1, 18.2, 18.3, 18.8

>[!important]  Korisno
>- komandom `ln` se mogu kreirati hard linkovi. Komandom `ln -s` se mogu kreirati simbolički linkovi. Može biti korisno zarad testiranja na ispitu.

---
# 5. cas

- Ovde je uglavnom sve isto kao na 4. casu, prolazak kroz direktorijum sa `nftw` funkcijom i obrada fajlova
![[Pasted image 20231119175850.png]]
- Jedina nova stvar je obrada vremena koju me sad mrzi da pisem

> [!important] TLPI poglavlja
> - 18 - nftw
> - 10-10.2


---

# 6. cas
## Procesi
- Za rad sa procesima najbitnije su nam funkcije `fork`, `exit`, `wait` i neka od varijacija `exec` funkcije.

- `fork()` sistemski poziv omogucava procesu tj. roditelju da kreira `dete` proces koji je u potpunosti nezavisan on njega i sa kojim nema direktan nacin komunikacije, ali `dete` proces dobija istu kopiju podataka koje je imao i roditelj (`stack` , `heap`, `data` i `text` segmente iz memorije). 

- `exit()` kada pozovemu, proces se prekida i tada su svi resursi koje je on koristio oslobodjeni i prepusteni kernelu da ih on realocira, funkcija `exit()` obicno prima kao argument `int EXIT_STATUS` koji ima u glavnom vrednost 0 ili 1, gde 0 oznacava uspeh a 1 neuspeh u izvrsavanju.

- `wait()` koristimo da bi suspendovali dalje izvrsavanje procesa dok se `dete` ne zavrsi odnosno prekine `exit` pozivom, `wait` takodje vraca status zavrsetka `deteta` 

![[Pasted image 20231119162940.png]]
- Dijagram kreiranja `deteta`, njegovog zivota i unistenja.

-  U programu mozemo da uz pomoc funkcije `fork` da kreiramo novi proces kome je nas vec pokrenut program `parent`. Funkcija `fork()` vraca `pid_t` tip podatka odnosno ceo broj koji oznacava ID naseg novog procesa.

- Proces `dete` ima ID 0 dok je PID `roditelja` uvek veci od nula i tako mozemo da ih i obradjujemo.

```C
pid_t childPid = fork();
check_error(childPid != -1, "fork failed");

if (childPid > 0) { // parent branch
	printf("Parent. PPID: %jd, CPID: %jd\n", \
        (intmax_t)getpid(), (intmax_t)childPid);
} else { // child branch
    printf("Child. CPID: %jd, PPID: %jd\n", \
        (intmax_t)getpid(), (intmax_t)getppid());
}

printf("We both execute this\n")
```
- Ovaj kod kreira `dete` proces i iz njega ispisuje "Child".  Nakon sto se oba procesa izvrse program ce se nastaviti sa izvrsavanjem `roditelj` i `dete` ce stici do `printf()` funkcije


```C
pid_t childPid = fork();
check_error(childPid != -1, "fork failed");

if (childPid > 0) { // parent branch
	printf("Parent. PPID: %jd, CPID: %jd\n", \
        (intmax_t)getpid(), (intmax_t)childPid);
} else { // child branch
    printf("Child. CPID: %jd, PPID: %jd\n", \
        (intmax_t)getpid(), (intmax_t)getppid());
    exit(EXIT_SUCCESS)
}

printf("Only parrent\n")
```
- Kod je isit kao gore samo sto se `dete` ubija i ostaje samo `roditelj`. `roditelji` bez `dece` se zovu zombi procesi, tako da nakon svakog `fork` moramo da imamo i `wait` gde cemo obraditi zombi procese da ne bi zagusivali sistem.

- Isto tako moramo da vodimo i racuna o `sirocicima` ('orphans'). Siroce je `dete` kojem je roditelj zavrsen pre njega.

>[!todo] Obavezne stvari za cist i dobar kod
> `malloc` i `free`
> `open` i `close`
> `fork` i `wait`

- S obzirom da `dete` dobija kopiju svih podataka koje je imao `roditelj` i da se oni izvrsavaju potpuno izolovano jedan od drugog, svaka promenljiva koju definisemo pre `fork` ce biti dodeljena `detetu` tj. kopije tih promenljivih

```C
int var = 5;
pid_t childPid = fork();
check_error(childPid != -1, "fork failed");

if (childPid > 0) { // parent branch
	printf("Parent);
	   
} else { // child branch
	printf("Child:\n");
	var *= 2;

	printf("Var in child: %d\n", var);
	exit(EXIT_SUCCESS);
}

int status;
check_error(wait(&status) != -1, "wait failed");

if (WIFEXITED(status))
	printf("Exit code: %d\n", WEXITSTATUS(status));
else
	printf("Process exited abnormally\n");

printf("Only parent executes this\n");
printf("Var in parent: %d\n", var);
exit(EXIT_SUCCESS);
```
- Ovaj kod ispisuje promenljivu var i proverava na kraju status kako se `dete` zavrsilo. 
- Izlaz ovog koda:
```
Hello from parent. My pid is 44274, child pid is 44275
Hello from child. My pid is 44275, parent pid is 44274
Var in child: 10
Process exited normally. Exit code: 0
Only parent executes this
Var in parent: 5
```

### Redirekcija ulaza i izlaza procesa koriscenjem pipe-ova

- Pipe se na UNIX sistemima koristi tako da izlaz jednog procesa preusmerimo da bude ulaz drugog procesa. 
- Pipe uvek mora da bude jednosmeran, odnsno samo da radi na relaciji izlaz -> ulaz za dva procesa.
- Ovo nam omogucava sistemski poziv `pipe` koji za dati niz celih brojeva od 2 elementa otvara 2 fajl deskriptora. Fajl deskriptor na poziciji nula je uvek za citanje, dok je na poziciji 1 uvek za pisanje; 
```
int p[2];
pipe(p);
// p[0] - read end - RD_E
// p[1] - write end - WR_E
```

- Implementacija pipe-a za `dete` i `roditelja`:
	1. Kreiramo dva niza celih brojeva sa po dva elementa
	2. sistemskim pozivom `pipe` kreiramo pipeove za relacije `deteRoditelj` i `roditeljDete`
	3.  Kreiramo `dete` sa `fork`
	4. Zatvarmo nepotrebne fajl deskriptore da bi omogucili jednosmeran protok informacija, ovo zatvarenje fajlova radimo zato sto oba procesa dobijaju kopije podataka
		1. U `roditelju` zatvarmo `deteRoditelj[WR_E]` i `roditeljDete[RD_E]`
		2. U `detetu` zatvarom `deteRoditelj[RD_E]` i `roditeljDete[WR_E]`
	6. U parentu kreiramo poruku i pisemo u fajl deskriptor `roditeljDete[WR_E]` 
	7. Zatim u `detetu` citamo iz `roditeljDete[RD_E]` i obradjujemo dalje poruku

```C
int childToParent[2];
int parentToChild[2];

check_error(pipe(childToParent) != -1, "pipe");
check_error(pipe(parentToChild) != -1, "pipe");

pid_t childPid = fork();
check_error(childPid != -1, "fork");

if (childPid > 0) {// parrent

	close(parentToChild[RD_END]);
	close(childToParent[WR_END]);

	char buffer[BUFF_SIZE];
	sprintf(buffer, "%s", "Hello child\n");

	check_error(write(parentToChild[WR_END], buffer, strlen(buffer)) != -1, "write parrent");

	// recive message from child
	char message[BUFF_SIZE];
	int readBytes = read(childToParent[RD_END], message, BUFF_SIZE);

	check_error(readBytes != -1, "read parent");
	message[readBytes] = 0;

	printf("Child message: %s\n", message);

	// close reaminging fd's
	close(parentToChild[WR_END]);
	close(childToParent[RD_END]);
} else {// child

	close(childToParent[RD_END]);
	close(parentToChild[WR_END]);

	char message[BUFF_SIZE];
	int readBytes = read(parentToChild[RD_END], message, BUFF_SIZE);
	check_error(readBytes != -1, "read");
	message[readBytes] = 0;

	char buffer[BUFF_SIZE];
	sprintf(buffer, "Parrent message: %s", message);

	printf("%s\n", buffer);

	// send message to prent
	sprintf(buffer, "%s", "Hello father\n");

	check_error(write(childToParent[WR_END], buffer, strlen(buffer)) != -1, "write child");

	close(childToParent[WR_END]);
	close(parentToChild[RD_END]);

	exit(EXIT_SUCCESS);

}

check_error(wait(NULL) != -1, "wait");
exit(EXIT_SUCCESS);
```
- Ovaj kod predstavlja implementaciju gore navedenog procesa stvaranja pipe-a

###  Exec 
- Varijacije funkcije `exec` nam omugcavaju da iz naseg programa porkecemo druge programe, za razliku od `fork` koji vrsi kopiranje adresnog prostora i dodeljuje ga `child` procesu, `exec` vrsi zamenu adresnog prostora i nas program vise ne postoji kao proces vec je njegov prostor dodeljen novom procesu

- `exec` porodica funkcija se deli na:
	1. `execl`:
		1. `execlp`
		2. `execle`
	2. `execv`:
		1. `execvp`
		2. `execvpe`

`execl` koriste niz NULL-terminirajucih nizova karaktera kao argumente
`execv` koriste `char **arguments` kao argumente funckije koje pozivaju, prvi element ovog niza arguments se uvek koristi kao ime fajla kojeg pozivamo.


```C
int main(int argc, char** argv) {

	check_error(execlp("ls", "ls", "-l", NULL) != -1, "exec failed");

	printf("Ovaj deo koda se ne izvrsava\n");
    exit(EXIT_SUCCESS);
}
```
- Ovaj kod poziva funkciju `ls` sa arugmentima `-l` koji vrsi ispisivanje sadrzaja trenutnog direktorijuma. Ovde za poziv `ls -l` koristimo funkciju `execlp` 

```C
char** arguments = malloc(argc * sizeof(char*));
check_error(arguments != NULL, "");

for(int i = 1; i < argc; i++){
	arguments[i-1] = malloc(strlen(argv[i]) + 1);
	check_error(arguments[i-1] != NULL, "");
	strcpy(arguments[i-1], argv[i]);
}

arguments[argc - 1] = NULL;
pid_t childPid = fork();
check_error(childPid != -1, "");

if(childPid == 0){
	check_error(execvp(arguments[0], arguments) != -1, "");
	exit(EXIT_SUCCESS);
}

int status = 0;
check_error(wait(&status) != -1, "");
if(WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_SUCCESS)){
	printf("success\n");
} else {
	printf("fail\n");
}

exit(EXIT_SUCCESS);
```
- Ovaj kod implmentria `execvp` i pokazuje nacin na koji se on implementira i pritom koristi `dete` proces da se adresni prostor koji koristi `roditelj` ne bi obrisao i sto omogucava dalje izvrsavanje programa nakon sto `dete` pozove `exec` i zavrsi se.
- Sa `wait` se brinemo o tome da se ne stvaraju zombiji, i tu zavrsavamo i izvrsavanje roditelja

> [!important] TLPI poglavlja
> - 24-24.2
> - 26.1-26.1.3, 26.2
> - 27-27.4
> - 44-44.4

---
# 7. cas








> [!important] TLPI poglavlja
> - 20, 20.1, 20.2, 20.3, 20.4, 20.5, 20.14
> - 21.1.2
> - 44.7, 44.8, 44.10

---
