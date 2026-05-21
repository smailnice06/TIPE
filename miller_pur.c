#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

// Fonction exportée pour Python
int miller_rabin_custom_gmp(const char* n_str, int k) {
    // 1. Déclaration de TOUTES les variables GMP nécessaires
    mpz_t n, n_minus_1, d, a, x, range;
    mpz_inits(n, n_minus_1, d, a, x, range, NULL);
    
    int resultat = 1; // On suppose que le nombre est premier au départ

    

    // 2. Conversion du texte Python en grand entier GMP
    if (mpz_set_str(n, n_str, 10) != 0) {
        mpz_clears(n, n_minus_1, d, a, x, range, NULL);
        return 0;
    }

    // --- CAS DE BASE ---
    if (mpz_cmp_ui(n, 2) < 0) { resultat = 0; goto cleanup; }
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) { resultat = 1; goto cleanup; }
    if (mpz_even_p(n)) { resultat = 0; goto cleanup; } // Si c'est pair, c'est mort

    // --- FILTRE RAPIDE (TRIAL DIVISION) ---
    // Les 25 premiers nombres premiers (pour éliminer ~75% des nombres non-premiers)
    const unsigned long petits_premiers[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 
        43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
    };
    int nb_petits_premiers = sizeof(petits_premiers) / sizeof(petits_premiers[0]);

    for (int i = 0; i < nb_petits_premiers; i++) {
        // mpz_divisible_ui_p renvoie >0 si n est divisible par le petit premier
        if (mpz_divisible_ui_p(n, petits_premiers[i])) {
            // Si n == petit_premier, c'est qu'il est premier
            if (mpz_cmp_ui(n, petits_premiers[i]) == 0) {
                resultat = 1;
            } else {
                resultat = 0; // Il est divisible, donc composé !
            }
            goto cleanup; // On quitte immédiatement, on a gagné un temps fou !
        }
    }
    // Si on arrive ici, le nombre n'est divisible par aucun petit nombre premier.
    // ON PEUT ENFIN LANCER MILLER-RABIN !

    // --- ÉTAPE 1 : Décomposition de n-1 = d * 2^r ---
    mpz_sub_ui(n_minus_1, n, 1); // n_minus_1 = n - 1
    mpz_set(d, n_minus_1);
    
    // mpz_scan1 trouve la position du premier bit à '1' (ce qui donne r)
    unsigned long r = mpz_scan1(d, 0); 
    // On divise d par 2^r (décalage de bits vers la droite)
    mpz_tdiv_q_2exp(d, d, r); 

    // --- ÉTAPE 2 : Préparation du générateur aléatoire cryptographique ---
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);

    // Ouverture de la source d'entropie du système (macOS/Linux)
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        unsigned char seed_bytes[32]; // On extrait 256 bits d'entropie pure
        fread(seed_bytes, 1, sizeof(seed_bytes), urandom);
        fclose(urandom);

        // Conversion du tableau d'octets en un grand entier GMP (mpz_t)
        mpz_t true_seed;
        mpz_init(true_seed);
        
        // mpz_import est la fonction GMP pour ingérer des données binaires brutes
        mpz_import(true_seed, sizeof(seed_bytes), 1, sizeof(seed_bytes[0]), 0, 0, seed_bytes);
        
        // Initialisation du générateur avec notre graine surpuissante
        gmp_randseed(rand_state, true_seed);
        mpz_clear(true_seed);
    } else {
        // Fallback de sécurité (très peu probable sur Mac, mais bonne pratique d'ingénierie)
        gmp_randseed_ui(rand_state, time(NULL));
    }

    // La plage de l'aléatoire 'a' doit être [0, n-4] pour qu'en ajoutant 2, on ait [2, n-2]
    mpz_sub_ui(range, n, 3);

    

    // --- ÉTAPE 3 : La boucle de test (k fois) ---
    for (int i = 0; i < k; i++) {
        // Tirage de a au sort
        mpz_urandomm(a, rand_state, range);
        mpz_add_ui(a, a, 2); // a = a + 2

        // Le coeur du réacteur : x = (a^d) % n (L'exponentiation modulaire ultra rapide de GMP)
        mpz_powm(x, a, d, n);

        // Si x == 1 ou x == n - 1, on passe au test suivant
        if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_minus_1) == 0) {
            continue;
        }

        int est_compose = 1; // On suppose qu'il est composé pour ce test
        
        // Boucle des r-1 carrés
        for (unsigned long j = 1; j < r; j++) {
            mpz_powm_ui(x, x, 2, n); // x = (x^2) % n
            
            if (mpz_cmp(x, n_minus_1) == 0) {
                est_compose = 0; // Finalement, c'est un bon candidat
                break;
            }
        }

        if (est_compose == 1) {
            resultat = 0; // Preuve irréfutable que le nombre est composé
            break;
        }
    }

    gmp_randclear(rand_state);

cleanup:
    // 3. Libération obligatoire de la mémoire (sinon ton Mac va planter !)
    mpz_clears(n, n_minus_1, d, a, x, range, NULL);
    return resultat;
}