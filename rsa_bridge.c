#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>

#define MR_ITERATIONS 40

pthread_mutex_t prime_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int primes_found = 0;
mpz_t p_rsa, q_rsa;
int target_bit_length;

// --- STRUCTURE POUR PYTHON ---
typedef struct {
    char *n; char *d; char *p; char *q; char *dp; char *dq; char *qinv;
} RSAKeys_C;

// --- FONCTION MILLER-RABIN OPTIMISÉE ---
int miller_rabin_core(mpz_t n, int k, gmp_randstate_t rand_state) {
    if (mpz_cmp_ui(n, 2) < 0) return 0;
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) return 1;
    if (mpz_even_p(n)) return 0;

    const unsigned long petits_premiers[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 
        43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97
    };
    int nb_petits_premiers = sizeof(petits_premiers) / sizeof(petits_premiers[0]);

    for (int i = 0; i < nb_petits_premiers; i++) {
        if (mpz_divisible_ui_p(n, petits_premiers[i])) {
            return (mpz_cmp_ui(n, petits_premiers[i]) == 0) ? 1 : 0;
        }
    }

    mpz_t n_minus_1, d, a, x, range;
    mpz_inits(n_minus_1, d, a, x, range, NULL);
    
    mpz_sub_ui(n_minus_1, n, 1);
    mpz_set(d, n_minus_1);
    unsigned long r = mpz_scan1(d, 0); 
    mpz_tdiv_q_2exp(d, d, r); 

    mpz_sub_ui(range, n, 3);
    int resultat = 1;

    for (int i = 0; i < k; i++) {
        mpz_urandomm(a, rand_state, range);
        mpz_add_ui(a, a, 2); 
        mpz_powm(x, a, d, n);

        if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_minus_1) == 0) continue;

        int est_compose = 1; 
        for (unsigned long j = 1; j < r; j++) {
            mpz_powm_ui(x, x, 2, n);
            if (mpz_cmp(x, n_minus_1) == 0) {
                est_compose = 0;
                break;
            }
        }

        if (est_compose == 1) {
            resultat = 0;
            break;
        }
    }

    mpz_clears(n_minus_1, d, a, x, range, NULL);
    return resultat;
}

// --- WORKER POUR CHAQUE CŒUR ---
void* find_prime_worker(void* thread_id) {
    long tid = (long)thread_id;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        unsigned long int seed;
        fread(&seed, sizeof(seed), 1, urandom);
        fclose(urandom);
        gmp_randseed_ui(state, seed + tid); 
    } else {
        gmp_randseed_ui(state, time(NULL) + tid);
    }

    mpz_t candidate;
    mpz_init(candidate);

    while (primes_found < 2) {
        mpz_urandomb(candidate, state, target_bit_length);
        mpz_setbit(candidate, 0);
        mpz_setbit(candidate, target_bit_length - 1);

        if (miller_rabin_core(candidate, MR_ITERATIONS, state)) {
            pthread_mutex_lock(&prime_mutex);
            if (primes_found == 0) {
                mpz_set(p_rsa, candidate);
                primes_found++;
            } else if (primes_found == 1 && mpz_cmp(p_rsa, candidate) != 0) {
                mpz_set(q_rsa, candidate);
                primes_found++;
            }
            pthread_mutex_unlock(&prime_mutex);
        }
    }

    mpz_clear(candidate);
    gmp_randclear(state);
    return NULL;
}

// Utilitaire pour convertir proprement un mpz_t en string standard
char* get_mpz_str(mpz_t op) {
    size_t size = mpz_sizeinbase(op, 10) + 2;
    char* str = malloc(size);
    mpz_get_str(str, 10, op);
    return str;
}

// ========================================================
// LES DEUX FONCTIONS EXPORTÉES POUR PYTHON (CTYPES)
// ========================================================

__attribute__((visibility("default")))
RSAKeys_C generate_rsa_keys_ctypes(int bit_length, int num_cores) {
    target_bit_length = bit_length;
    primes_found = 0;
    mpz_inits(p_rsa, q_rsa, NULL);

    pthread_t threads[num_cores];
    for (long i = 0; i < num_cores; i++) {
        pthread_create(&threads[i], NULL, find_prime_worker, (void*)i);
    }
    for (int i = 0; i < num_cores; i++) {
        pthread_join(threads[i], NULL);
    }

    gmp_randstate_t main_state;
    gmp_randinit_default(main_state);
    gmp_randseed_ui(main_state, time(NULL));

    mpz_t n, phi, p_minus_1, q_minus_1, e, d, gcd, dp, dq, qinv;
    mpz_inits(n, phi, p_minus_1, q_minus_1, e, d, gcd, dp, dq, qinv, NULL);

    mpz_mul(n, p_rsa, q_rsa);
    mpz_sub_ui(p_minus_1, p_rsa, 1);
    mpz_sub_ui(q_minus_1, q_rsa, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);

    mpz_set_ui(e, 65537);
    mpz_gcd(gcd, e, phi);
    while (mpz_cmp_ui(gcd, 1) != 0) {
        mpz_urandomm(e, main_state, phi);
        mpz_setbit(e, 0); 
        if (mpz_cmp_ui(e, 3) < 0) mpz_set_ui(e, 3);
        mpz_gcd(gcd, e, phi);
    }

    mpz_invert(d, e, phi);
    mpz_mod(dp, d, p_minus_1);
    mpz_mod(dq, d, q_minus_1);
    mpz_invert(qinv, q_rsa, p_rsa);

    // On remplit la structure Python
    RSAKeys_C keys;
    keys.n = get_mpz_str(n);
    keys.d = get_mpz_str(d);
    keys.p = get_mpz_str(p_rsa);
    keys.q = get_mpz_str(q_rsa);
    keys.dp = get_mpz_str(dp);
    keys.dq = get_mpz_str(dq);
    keys.qinv = get_mpz_str(qinv);

    mpz_clears(p_rsa, q_rsa, n, phi, p_minus_1, q_minus_1, e, d, gcd, dp, dq, qinv, NULL);
    gmp_randclear(main_state);

    return keys;
}

// Fonction capitale pour éviter les Memory Leaks !
__attribute__((visibility("default")))
void free_rsa_keys_ctypes(RSAKeys_C keys) {
    free(keys.n);
    free(keys.d);
    free(keys.p);
    free(keys.q);
    free(keys.dp);
    free(keys.dq);
    free(keys.qinv);
}