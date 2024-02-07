# Ispitna pitanja

## Prva glava 

1. Racunarski sistem se sastoji od hardvera i softvera

2. Operativni sistem je softver najnizeg nivoa koji ide direkntno na hardver i on treba da obezbedi sto bolje uslove za koriscenje racunara. Operativni sitem se takodje naziva menadzer resursa.
- Upravljanje procesorom 
- Upravljanje memorijom
- Upravljanje I/O uredjajma
- Upravljanje mrezama
- Upravljanje podacima (File system)

3. Softver se deli na sistemski i aplikativni. Sistemski softver omogucava koriscenje racunara, dok aplikativni resava korisnicke probleme.

4. Sistemski softver moze da sadrzi editore, programe za sortiranje i prevodioce, oni nisu neophodni za sistem ali znacajno olaksavaju rad

5. Hardver i sistemski softver se nazivaju drugacije i virtuelna masina. Virtuelna masina predstavlja skup mogucnosti koje se prezentuju kao funkcije koje procesor moze da izvrsi

6. Kernel (jezgro) operativnog sistema je deo operativnog sistema u koji su smestene najvazinije funkcije koje obezbedjuju osnove servise operativnog sistema, on se prvi ucitava u radnu memoriju i u njoj ostaje do zavrsetka rada odnosno do iskljucivanja, jezgro se takodje nalazi u posebnom delu memorije i stalno je aktivno, i najnizi je sloj u racunarskom sistemu koji nije hardver.

7. Jezgro takodje obezbedjuje:
    - Konkurentno izvrsavanje procesa
    - dodeljuje memoriju
    - sprecava korisnicke procese od direktnog pristupanja harveru vec se koriste sistemski pozivi
    - sistemski programi koriste krenel da se omogucila implementacija raznih servisa operativnog sistema

8. Sistemski programi:
    - Svi programi rade na nivou iznad kernela
    - To se naziva korisnicki rezim, dok se pristup hard disku na primer odvija u sistemskom rezimu
    - Razlika izmedju sistemski i korisnickih programa je u nameni, korisnicki program npr. za obradu teksta dok je mount sistemski program

9. Sistemski pozivi:
    - Usluge koje sistem pruza aplikativnom softveru se izvrsavaju preko sistemski poziva
    - Programi uz pomoc sistemskih poziva komunuiciraju sa jezgrom i tako dobija mogucnost da izvrsava osetljive operacije
    - Aplikativni softver moze da pristupi hard disku ili stampacu samo uz pomoc odgovorajuce sistemskog poziva
    - Implementirani su tako da mogu da dozvole samo operacije koje nisu stetne za sistem, i dozvoljene operacije su jasno definisane
    - tok sistemskih poziva:

10. Arhitekture sistema:
    - Monolitni
    - Slojeviti
    - Mikrojezgro
    - Hibridni
    - Egzojezgro


