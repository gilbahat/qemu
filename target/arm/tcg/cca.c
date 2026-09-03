/*
 * Emulated Arm CCA guest interface (RSI) for TCG.
 *
 * A Realm talks to the Realm Management Monitor through RSI, a set of SMCs.
 * On hardware the RMM is real software running at R-EL2 and the CPU is in
 * Realm state; neither exists here.  What this provides is the guest's half of
 * that conversation, in the same spirit as the emulated TDX and SEV-SNP guest
 * ABIs in target/i386: enough for a Realm-aware guest to boot, discover its
 * configuration and be developed against, on a machine with no RME silicon and
 * without the two-level TF-A/TF-RMM stack.
 *
 * It is not a Realm.  Nothing here is measured by anything trustworthy and
 * nothing enforces confidentiality; the guest is told so on stderr at start-up.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/lockable.h"
#include "exec/cputlb.h"
#include "hw/arm/cca-dma.h"
#include "cpu.h"
#include "internals.h"
#include "system/memory.h"

/*
 * RSI function IDs.  All are SMC64 with the standard-service owning entity, so
 * they sit next to PSCI in the same 0xc4xxxxxx range -- which is why the
 * dispatch below matches on the whole ID rather than the owning entity.
 */
#define RSI_ABI_VERSION             0xc4000190
#define RSI_MEASUREMENT_EXTEND      0xc4000193
#define RSI_ATTESTATION_TOKEN_INIT  0xc4000194
#define RSI_ATTESTATION_TOKEN_CONT  0xc4000195
#define RSI_REALM_CONFIG            0xc4000196
#define RSI_IPA_STATE_SET           0xc4000197

#define RSI_SUCCESS                 0
#define RSI_ERROR_INPUT             1
#define RSI_ERROR_STATE             2
#define RSI_INCOMPLETE              3

/* SMCCC's answer for a function this implementation does not provide. */
#define SMCCC_RET_NOT_SUPPORTED     ((uint64_t)-1)

/* The only interface version implemented, as major<<16 | minor. */
#define RSI_ABI_VERSION_1_0         (1u << 16)

/* RIPAS values a guest may ask for. */
#define RSI_RIPAS_EMPTY             0
#define RSI_RIPAS_RAM               1
#define RSI_RIPAS_DESTROYED         2
#define RSI_RIPAS_DEV               3

/* RSI_IPA_STATE_SET response: the host accepted the change. */
#define RSI_ACCEPT                  0

#define RSI_GRANULE_SIZE            4096

/* x-cca-ripas: how much of the page-state model is enforced. */
#define CCA_RIPAS_MODE_OFF          0
#define CCA_RIPAS_MODE_LAZY         1
#define CCA_RIPAS_MODE_STRICT       2

/*
 * Realm IPA state, as much of it as a guest can observe.
 *
 * A Realm's protected memory is RAM until the guest hands a range back with
 * RSI_IPA_STATE_SET(EMPTY), which is how it makes room to use the unprotected
 * alias of those pages instead.  Only granules whose state differs from the
 * default are stored, so there is nothing to size against guest RAM and
 * nothing to grow when memory is hotplugged.
 */
typedef struct CcaTcgState {
    QemuMutex lock;
    GHashTable *ripas;
} CcaTcgState;

static CcaTcgState *cca_state;

static CcaTcgState *cca_get_state(void)
{
    if (!cca_state) {
        cca_state = g_new0(CcaTcgState, 1);
        qemu_mutex_init(&cca_state->lock);
    }
    return cca_state;
}

void arm_cca_init(void)
{
    cca_get_state();
}

static gpointer cca_ripas_key(uint64_t ipa)
{
    return GSIZE_TO_POINTER(ipa >> 12);
}

static uint64_t cca_ripas_get(uint64_t ipa)
{
    CcaTcgState *s = cca_get_state();
    gpointer v;
    bool found;

    QEMU_LOCK_GUARD(&s->lock);
    found = s->ripas &&
            g_hash_table_lookup_extended(s->ripas, cca_ripas_key(ipa),
                                         NULL, &v);
    /* Anything never spoken about is RAM, which is how a Realm starts. */
    return found ? GPOINTER_TO_SIZE(v) : RSI_RIPAS_RAM;
}

static void cca_ripas_set(uint64_t ipa, uint64_t ripas)
{
    CcaTcgState *s = cca_get_state();

    QEMU_LOCK_GUARD(&s->lock);
    if (!s->ripas) {
        s->ripas = g_hash_table_new(NULL, NULL);
    }
    g_hash_table_insert(s->ripas, cca_ripas_key(ipa),
                        GSIZE_TO_POINTER(ripas));
}

/*
 * Is this access allowed, given which half of the address space it came
 * through?  @ipa has already had the alias bit folded away.
 *
 * Two things can be wrong, and they are opposite mistakes:
 *
 *  - reaching a granule through the *protected* view after handing it back.
 *    A real RMM has taken that mapping away; here it would silently keep
 *    working, and a guest that leaves a pointer behind would never find out.
 *
 *  - reaching a granule through the *unprotected alias* without handing it
 *    back first.  On hardware nothing is mapped there until the host maps it,
 *    so the access goes nowhere.  Only strict mode says so, because a guest
 *    may legitimately touch the alias of a device window it never owned.
 */
bool arm_cca_ipa_permitted(CPUARMState *env, uint64_t ipa, bool shared)
{
    ARMCPU *cpu = env_archcpu(env);
    uint64_t ripas;

    if (!cpu->cca_guest || cpu->cca_ripas == CCA_RIPAS_MODE_OFF) {
        return true;
    }

    ripas = cca_ripas_get(ipa);

    if (!shared && ripas == RSI_RIPAS_EMPTY) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: protected access to 0x%" PRIx64 ", which the "
                      "Realm handed back with RSI_IPA_STATE_SET\n", ipa);
        return false;
    }

    if (shared && ripas != RSI_RIPAS_EMPTY &&
        cpu->cca_ripas == CCA_RIPAS_MODE_STRICT) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: access through the unprotected alias of 0x%"
                      PRIx64 ", which the Realm has not handed back\n", ipa);
        return false;
    }

    return true;
}

bool arm_cca_gpa_is_shared(CPUARMState *env, uint64_t ipa)
{
    /*
     * With no page-state model there is nothing to ask, and a filter that
     * refused everything would simply stop every device.
     */
    if (env_archcpu(env)->cca_ripas == CCA_RIPAS_MODE_OFF) {
        return true;
    }
    return cca_ripas_get(ipa) == RSI_RIPAS_EMPTY;
}

bool arm_is_cca_call(ARMCPU *cpu, int excp_type)
{
    uint64_t fid;

    if (!cpu->cca_guest || excp_type != EXCP_SMC || !is_a64(&cpu->env)) {
        return false;
    }

    /*
     * Claim the whole RSI range, not just the calls implemented below, so that
     * an unimplemented one is answered as RSI would answer it rather than
     * falling through to the PSCI handler and being reported as a PSCI error.
     */
    fid = cpu->env.xregs[0];
    return fid >= RSI_ABI_VERSION && fid <= RSI_IPA_STATE_SET;
}

/*
 * RSI_REALM_CONFIG writes a 4KiB configuration structure into Realm memory.
 * Only the first field matters to anything that runs here: the IPA width, from
 * which a guest derives the bit that distinguishes protected from unprotected
 * addresses.  The rest is written as zeroes rather than left alone, because a
 * guest is entitled to read the whole granule and a real RMM fills it.
 */
static uint64_t cca_realm_config(ARMCPU *cpu, uint64_t addr)
{
    g_autofree uint8_t *cfg = g_malloc0(RSI_GRANULE_SIZE);

    if (addr & (RSI_GRANULE_SIZE - 1)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_REALM_CONFIG buffer 0x%" PRIx64 " is not "
                      "granule-aligned\n", addr);
        return RSI_ERROR_INPUT;
    }

    stq_le_p(cfg, cpu->cca_ipa_bits);   /* ipa_width */
    stq_le_p(cfg + 8, 0);               /* hash algorithm: SHA-256 */

    if (address_space_write(arm_addressspace(CPU(cpu), MEMTXATTRS_UNSPECIFIED),
                            addr, MEMTXATTRS_UNSPECIFIED, cfg,
                            RSI_GRANULE_SIZE) != MEMTX_OK) {
        return RSI_ERROR_INPUT;
    }
    return RSI_SUCCESS;
}

/*
 * RSI_IPA_STATE_SET changes the state of a range of protected IPA.  The reply
 * reports how far the change was made, and a guest is required to loop on it;
 * returning the base unchanged is a failure rather than a request to retry, so
 * this always advances to the top of the range.
 *
 * The state itself is not recorded yet.  The half of the promise a guest
 * actually depends on does hold -- the unprotected alias of the range reaches
 * the same memory, because the translation path folds the alias bit away --
 * but the other half does not: the protected view remains readable, where a
 * real RMM would have taken it away.  A guest that keeps using it after
 * relinquishing is therefore not yet caught, which is what the page-state
 * model is for.
 */
static uint64_t cca_ipa_state_set(ARMCPU *cpu, uint64_t base, uint64_t top,
                                  uint64_t ripas, uint64_t flags,
                                  uint64_t *new_base, uint64_t *response)
{
    if ((base & (RSI_GRANULE_SIZE - 1)) || (top & (RSI_GRANULE_SIZE - 1)) ||
        top <= base) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_IPA_STATE_SET range 0x%" PRIx64 "-0x%" PRIx64
                      " is not a non-empty granule-aligned range\n", base, top);
        return RSI_ERROR_INPUT;
    }
    if (ripas > RSI_RIPAS_DEV) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_IPA_STATE_SET asks for RIPAS %" PRIu64
                      ", which is not a defined value\n", ripas);
        return RSI_ERROR_INPUT;
    }

    for (uint64_t ipa = base; ipa < top; ipa += RSI_GRANULE_SIZE) {
        cca_ripas_set(ipa, ripas);
    }

    /*
     * Handing a range back takes access away, so anything already cached for
     * it has to go.  A transition the other way only adds access and cannot
     * leave a stale entry behind, which is worth keeping in mind before making
     * this unconditional: a guest claiming memory does it a granule at a time.
     */
    if (ripas != RSI_RIPAS_RAM) {
        tlb_flush(CPU(cpu));
    }

    *new_base = top;
    *response = RSI_ACCEPT;
    return RSI_SUCCESS;
}

void arm_handle_cca_call(ARMCPU *cpu)
{
    CPUARMState *env = &cpu->env;
    uint64_t ret;

    /*
     * The guest has proved it knows where it is, so device DMA is now
     * something it is responsible for getting right.
     */
    cca_dma_arm();

    switch (env->xregs[0]) {
    case RSI_ABI_VERSION:
        /*
         * The reply is the closed interval of versions implemented, which the
         * guest checks its request against.  Both ends are 1.0.
         */
        env->xregs[1] = RSI_ABI_VERSION_1_0;
        env->xregs[2] = RSI_ABI_VERSION_1_0;
        ret = RSI_SUCCESS;
        break;

    case RSI_REALM_CONFIG:
        ret = cca_realm_config(cpu, env->xregs[1]);
        break;

    case RSI_IPA_STATE_SET: {
        uint64_t new_base = env->xregs[1];
        uint64_t response = RSI_ACCEPT;

        ret = cca_ipa_state_set(cpu, env->xregs[1], env->xregs[2],
                                env->xregs[3], env->xregs[4],
                                &new_base, &response);
        env->xregs[1] = new_base;
        env->xregs[2] = response;
        break;
    }

    default:
        qemu_log_mask(LOG_UNIMP,
                      "cca: RSI function 0x%" PRIx64 " is not implemented\n",
                      env->xregs[0]);
        ret = SMCCC_RET_NOT_SUPPORTED;
        break;
    }

    env->xregs[0] = ret;
}
