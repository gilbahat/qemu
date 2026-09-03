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
#include "qemu/error-report.h"
#include "crypto/hash.h"
#include "exec/cputlb.h"
#include "hw/arm/cca-dma.h"
#include "hw/core/loader.h"
#include "cpu.h"
#include "internals.h"
#include "cca-token.h"
#include "migration/vmstate.h"
#include "system/memory.h"
#include "system/reset.h"
#include "system/runstate.h"

/*
 * RSI function IDs.  All are SMC64 with the standard-service owning entity, so
 * they sit next to PSCI in the same 0xc4xxxxxx range -- which is why the
 * dispatch below matches on the whole ID rather than the owning entity.
 */
#define RSI_ABI_VERSION             0xc4000190
#define RSI_MEASUREMENT_READ        0xc4000192
#define RSI_MEASUREMENT_EXTEND      0xc4000193
#define RSI_ATTESTATION_TOKEN_INIT  0xc4000194
#define RSI_ATTESTATION_TOKEN_CONT  0xc4000195
#define RSI_REALM_CONFIG            0xc4000196
#define RSI_IPA_STATE_SET           0xc4000197
#define RSI_IPA_STATE_GET           0xc4000198

/*
 * The last function ID RSI 1.0 defines (RSI_HOST_CALL).  Nothing between here
 * and RSI_ABI_VERSION falls through to PSCI, implemented or not -- see
 * arm_is_cca_call().
 */
#define RSI_FID_LAST                0xc4000199

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

/*
 * RSI numbers the measurements 0..4.  Index 0 is the Realm Initial
 * Measurement, taken when the Realm is activated and read-only thereafter;
 * 1..4 are the Realm Extensible Measurements a guest may extend.
 */
#define RSI_MEASUREMENT_INDEX_MAX   CCA_REM_COUNT

/* The measurement travels in x1-x8 for a read and x3-x10 for an extend. */
#define RSI_MEASUREMENT_REGS        (CCA_MEASUREMENT_LEN / 8)

/*
 * The upper bound RSI_ATTESTATION_TOKEN_INIT reports.  It is a bound, not a
 * size: a guest sizes its buffer against it before the token exists.  One
 * granule is comfortably above what cca_build_token() produces and is what a
 * guest would have had to allocate anyway.
 */
#define RSI_TOKEN_MAX_SIZE          RSI_GRANULE_SIZE

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

    /*
     * Measurements.  The RIM is taken once at launch; the REMs are the
     * guest's own and go when the Realm does.
     */
    uint8_t rim[CCA_HASH_LEN];
    uint8_t rem[CCA_REM_COUNT][CCA_HASH_LEN];
    bool rim_valid;

    /*
     * What the loader placed in guest memory, in IPA order; the RIM is taken
     * over it.
     */
    Notifier rom_load_notifier;
    GSList *launch_regions;

    /*
     * An attestation token being handed over.  @token is NULL until the first
     * RSI_ATTESTATION_TOKEN_CONTINUE builds it, so that the bounded work a
     * real RMM does per call is visible to the guest rather than assumed away.
     */
    uint8_t challenge[CCA_CHALLENGE_LEN];
    bool token_requested;
    GByteArray *token;
    size_t token_off;

    /* Migration scratch; see vmstate_cca_tcg. */
    uint32_t ripas_count;
    uint64_t *ripas_gfn;
    uint8_t *ripas_st;
    uint32_t token_len;
    uint8_t *token_bytes;
    uint32_t token_taken;
} CcaTcgState;

typedef struct CcaLaunchRegion {
    hwaddr base;
    size_t size;
    const uint8_t *data;
} CcaLaunchRegion;

static CcaTcgState *cca_state;

/*
 * Realm-scoped state has to survive migration.
 *
 * The measurements above all: a REM that silently reset across a snapshot
 * would change the attestation token of a running Realm, which is the one
 * thing it must never do.  The page states go for the same reason they do in
 * the TDX emulation -- a Realm that has relinquished a range and is then
 * migrated would find every granule back at the default, and the alias it has
 * been using since would start faulting under a strict page-state mode.
 *
 * A token part-way through being handed over migrates as bytes rather than
 * being rebuilt on the far side.  Rebuilding would give the same bytes today,
 * because the token is a function of the challenge and the measurements, but
 * that is a property of the current builder rather than something the guest's
 * collection loop should depend on: it has already been told a length, and the
 * second half must belong to the same document as the first.
 *
 * The hash table is flattened into parallel arrays because a GHashTable has no
 * VMSTATE representation.
 */
static int cca_pre_save(void *opaque)
{
    CcaTcgState *s = opaque;
    GHashTableIter it;
    gpointer k, v;
    uint32_t i = 0;

    QEMU_LOCK_GUARD(&s->lock);

    s->ripas_count = s->ripas ? g_hash_table_size(s->ripas) : 0;
    g_free(s->ripas_gfn);
    g_free(s->ripas_st);
    s->ripas_gfn = g_new0(uint64_t, s->ripas_count);
    s->ripas_st = g_new0(uint8_t, s->ripas_count);

    if (s->ripas) {
        g_hash_table_iter_init(&it, s->ripas);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            s->ripas_gfn[i] = GPOINTER_TO_SIZE(k);
            s->ripas_st[i] = GPOINTER_TO_SIZE(v);
            i++;
        }
    }

    g_free(s->token_bytes);
    s->token_bytes = NULL;
    s->token_len = s->token ? s->token->len : 0;
    s->token_taken = (uint32_t)s->token_off;
    if (s->token_len) {
        s->token_bytes = g_memdup2(s->token->data, s->token_len);
    }
    return 0;
}

static int cca_post_load(void *opaque, int version_id)
{
    CcaTcgState *s = opaque;

    QEMU_LOCK_GUARD(&s->lock);

    if (!s->ripas) {
        s->ripas = g_hash_table_new(NULL, NULL);
    }
    g_hash_table_remove_all(s->ripas);
    for (uint32_t i = 0; i < s->ripas_count; i++) {
        g_hash_table_insert(s->ripas, GSIZE_TO_POINTER(s->ripas_gfn[i]),
                            GSIZE_TO_POINTER(s->ripas_st[i]));
    }

    if (s->token) {
        g_byte_array_free(s->token, TRUE);
        s->token = NULL;
    }
    if (s->token_len) {
        s->token = g_byte_array_sized_new(s->token_len);
        g_byte_array_append(s->token, s->token_bytes, s->token_len);
    }
    s->token_off = s->token_taken;

    /*
     * The page states just changed under every cached translation, so nothing
     * decided against the old ones may be reused.
     */
    tlb_flush_all_cpus_synced(first_cpu);
    return 0;
}

static const VMStateDescription vmstate_cca_tcg = {
    .name = "cca-tcg",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = cca_pre_save,
    .post_load = cca_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8_ARRAY(rim, CcaTcgState, CCA_HASH_LEN),
        VMSTATE_UINT8_2DARRAY(rem, CcaTcgState, CCA_REM_COUNT, CCA_HASH_LEN),
        VMSTATE_BOOL(rim_valid, CcaTcgState),
        VMSTATE_UINT8_ARRAY(challenge, CcaTcgState, CCA_CHALLENGE_LEN),
        VMSTATE_BOOL(token_requested, CcaTcgState),
        VMSTATE_UINT32(token_len, CcaTcgState),
        VMSTATE_UINT32(token_taken, CcaTcgState),
        VMSTATE_VBUFFER_ALLOC_UINT32(token_bytes, CcaTcgState, 0, NULL,
                                     token_len),
        VMSTATE_UINT32(ripas_count, CcaTcgState),
        VMSTATE_VARRAY_UINT32_ALLOC(ripas_gfn, CcaTcgState, ripas_count, 0,
                                    vmstate_info_uint64, uint64_t),
        VMSTATE_VARRAY_UINT32_ALLOC(ripas_st, CcaTcgState, ripas_count, 0,
                                    vmstate_info_uint8, uint8_t),
        VMSTATE_END_OF_LIST()
    }
};

static CcaTcgState *cca_get_state(void)
{
    if (!cca_state) {
        cca_state = g_new0(CcaTcgState, 1);
        qemu_mutex_init(&cca_state->lock);
    }
    return cca_state;
}

/* Discard the token in flight, if any.  The lock is held. */
static void cca_token_discard(CcaTcgState *s)
{
    if (s->token) {
        g_byte_array_free(s->token, TRUE);
        s->token = NULL;
    }
    s->token_off = 0;
    s->token_requested = false;
}

/*
 * A Realm does not survive a reset: the RMM tears it down, and what comes back
 * is a different Realm with a fresh measurement state.  So everything the
 * guest built goes, and only the RIM stays -- it measures the launch image,
 * which a reset does not reload.
 *
 * The page states go too, and this is not a detail.  Leaving them behind would
 * hand the next boot a set of granules the *previous* guest relinquished,
 * which it would then fault on while reading its own RAM.
 */
static void cca_reset(void *opaque)
{
    CcaTcgState *s = opaque;

    QEMU_LOCK_GUARD(&s->lock);
    if (s->ripas) {
        g_hash_table_remove_all(s->ripas);
    }
    memset(s->rem, 0, sizeof(s->rem));
    memset(s->challenge, 0, sizeof(s->challenge));
    cca_token_discard(s);
}

static bool cca_sha256(const struct iovec *iov, size_t niov, uint8_t *out)
{
    size_t len = CCA_HASH_LEN;

    return qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA256, iov, niov,
                               &out, &len, NULL) == 0;
}

static gint cca_compare_regions(gconstpointer a, gconstpointer b)
{
    const CcaLaunchRegion *ra = a;
    const CcaLaunchRegion *rb = b;

    return ra->base < rb->base ? -1 : 1;
}

/*
 * Record what the loader places in guest memory, sorted by IPA.
 *
 * This is the same notifier the KVM Realm VMM in this tree uses to decide what
 * to hand RMI_DATA_CREATE (see rme_rom_load_notify()), and sorted the same way
 * for the same reason: the RIM depends on the order the Realm is populated in,
 * so a verifier needs that order to be something it can reproduce.
 */
static void cca_rom_load_notify(Notifier *notifier, void *data)
{
    CcaTcgState *s = container_of(notifier, CcaTcgState, rom_load_notifier);
    RomLoaderNotifyData *rom = data;
    CcaLaunchRegion *region;

    /* Not loaded into guest RAM at reset; the guest fetches it itself. */
    if (rom->addr == -1) {
        return;
    }

    region = g_new0(CcaLaunchRegion, 1);
    region->base = rom->addr;
    region->size = rom->len;
    region->data = rom->data;

    QEMU_LOCK_GUARD(&s->lock);
    s->launch_regions = g_slist_insert_sorted(s->launch_regions, region,
                                              cca_compare_regions);
}

/*
 * The Realm Initial Measurement.
 *
 * Hardware builds this from the sequence of RMI calls that create the Realm
 * and populate it -- RMI_DATA_CREATE per granule, sealed by
 * RMI_REALM_ACTIVATE -- so the measurement covers each granule's contents and
 * the address it was placed at.  Nothing here performs that sequence, so this
 * hashes what would have gone through it: for every granule of every loaded
 * image, in IPA order, the IPA followed by the granule's contents.
 *
 * It is therefore **not** the RIM a real Realm would report for the same
 * image, and must not be compared against one.  What it is, is a root
 * measurement that is stable across boots, position-sensitive, and changes
 * when the image changes -- which is the part of an attestation flow that can
 * be tested without a Realm.
 *
 * Taken at the transition to running rather than at machine-init-done: ROMs
 * are copied into guest memory by the initial reset, which happens after every
 * machine-init-done notifier, so at that point there is nothing to measure.
 * By the time the VM runs the images are placed and no vCPU has executed,
 * which is when a Realm would be activated.
 */
static void cca_measure_launch_image(void *opaque, bool running, RunState state)
{
    CcaTcgState *s = opaque;
    g_autoptr(GByteArray) buf = g_byte_array_new();
    unsigned granules = 0;
    struct iovec iov;

    if (!running) {
        return;
    }

    QEMU_LOCK_GUARD(&s->lock);
    if (s->rim_valid) {
        return;
    }

    for (GSList *l = s->launch_regions; l; l = l->next) {
        const CcaLaunchRegion *r = l->data;

        for (size_t off = 0; off < r->size; off += RSI_GRANULE_SIZE) {
            uint8_t granule[RSI_GRANULE_SIZE] = { 0 };
            size_t n = MIN(RSI_GRANULE_SIZE, r->size - off);
            uint64_t ipa = cpu_to_le64(r->base + off);

            memcpy(granule, r->data + off, n);
            g_byte_array_append(buf, (const uint8_t *)&ipa, sizeof(ipa));
            g_byte_array_append(buf, granule, sizeof(granule));
            granules++;
        }
    }

    if (!granules) {
        warn_report("cca: no launch image found to measure; the RIM stays "
                    "zero");
        return;
    }

    iov.iov_base = buf->data;
    iov.iov_len = buf->len;
    if (!cca_sha256(&iov, 1, s->rim)) {
        warn_report("cca: failed to compute the RIM; it stays zero");
        return;
    }
    s->rim_valid = true;
    qemu_log_mask(LOG_GUEST_ERROR,
                  "cca: RIM computed over %u launch granules: "
                  "%02x%02x%02x%02x%02x%02x%02x%02x...\n", granules,
                  s->rim[0], s->rim[1], s->rim[2], s->rim[3],
                  s->rim[4], s->rim[5], s->rim[6], s->rim[7]);
}

/*
 * Called from CPU realize, so once per vCPU; the Realm is one thing and its
 * measurements, page states and notifiers are registered once.
 */
void arm_cca_init(void)
{
    static bool registered;
    CcaTcgState *s = cca_get_state();

    if (registered) {
        return;
    }
    registered = true;

    s->rom_load_notifier.notify = cca_rom_load_notify;
    rom_add_load_notifier(&s->rom_load_notifier);
    vmstate_register(NULL, 0, &vmstate_cca_tcg, s);
    qemu_add_vm_change_state_handler(cca_measure_launch_image, s);
    qemu_register_reset(cca_reset, s);
}

static gpointer cca_ripas_key(uint64_t ipa)
{
    return GSIZE_TO_POINTER(ipa >> 12);
}

static uint64_t cca_ripas_get_locked(CcaTcgState *s, uint64_t ipa)
{
    gpointer v;
    bool found = s->ripas &&
                 g_hash_table_lookup_extended(s->ripas, cca_ripas_key(ipa),
                                              NULL, &v);

    /* Anything never spoken about is RAM, which is how a Realm starts. */
    return found ? GPOINTER_TO_SIZE(v) : RSI_RIPAS_RAM;
}

static uint64_t cca_ripas_get(uint64_t ipa)
{
    CcaTcgState *s = cca_get_state();

    QEMU_LOCK_GUARD(&s->lock);
    return cca_ripas_get_locked(s, ipa);
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
    return fid >= RSI_ABI_VERSION && fid <= RSI_FID_LAST;
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

/*
 * RSI_MEASUREMENT_READ returns a measurement in x1-x8.  Index 0 is the RIM and
 * 1..4 are the REMs, so a guest that extends "register 0" of its own API has
 * to shift, and reading back what it just extended is how it finds out whether
 * it shifted the right way.
 *
 * A register is 64 bytes wide whatever the hash is.  SHA-256 fills the first
 * 32 and the rest reads as zero, which is what a real RMM returns too.
 */
static uint64_t cca_measurement_read(ARMCPU *cpu, uint64_t index)
{
    CcaTcgState *s = cca_get_state();
    uint8_t value[CCA_MEASUREMENT_LEN] = { 0 };

    if (index > RSI_MEASUREMENT_INDEX_MAX) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_MEASUREMENT_READ index %" PRIu64 " is above "
                      "the last measurement (%u)\n", index,
                      RSI_MEASUREMENT_INDEX_MAX);
        return RSI_ERROR_INPUT;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        memcpy(value, index == 0 ? s->rim : s->rem[index - 1], CCA_HASH_LEN);
    }

    for (unsigned i = 0; i < RSI_MEASUREMENT_REGS; i++) {
        cpu->env.xregs[1 + i] = ldq_le_p(value + i * 8);
    }
    return RSI_SUCCESS;
}

/*
 * RSI_MEASUREMENT_EXTEND folds a value into one of the four REMs.  The value
 * travels in x3-x10, which is why it takes a wider register window than
 * anything else in RSI, and only the first @size bytes of it count.
 *
 * REM[i] = SHA-256(REM[i] || value), with the value zero-padded to the full
 * 64-byte register width -- the shape TF-RMM uses.  The tail is zeroed here
 * rather than trusted, so a guest that leaves stale data in the registers
 * above @size gets the same answer a real RMM would give it.
 *
 * Index 0 is refused: the RIM is taken at activation and a Realm cannot extend
 * its own initial measurement.  That is the mistake this call is most likely
 * to be made with, so it is worth an error rather than a silent no-op.
 */
static uint64_t cca_measurement_extend(ARMCPU *cpu, uint64_t index,
                                       uint64_t size)
{
    CcaTcgState *s = cca_get_state();
    uint8_t value[CCA_MEASUREMENT_LEN] = { 0 };
    uint8_t current[CCA_HASH_LEN];
    struct iovec iov[2];

    if (index == 0 || index > RSI_MEASUREMENT_INDEX_MAX) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_MEASUREMENT_EXTEND index %" PRIu64 " is not "
                      "one of the extensible measurements (1-%u)\n", index,
                      RSI_MEASUREMENT_INDEX_MAX);
        return RSI_ERROR_INPUT;
    }
    if (size == 0 || size > CCA_MEASUREMENT_LEN) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_MEASUREMENT_EXTEND size %" PRIu64 " is not "
                      "between 1 and %u\n", size, CCA_MEASUREMENT_LEN);
        return RSI_ERROR_INPUT;
    }

    for (unsigned i = 0; i < RSI_MEASUREMENT_REGS; i++) {
        stq_le_p(value + i * 8, cpu->env.xregs[3 + i]);
    }
    memset(value + size, 0, CCA_MEASUREMENT_LEN - size);

    QEMU_LOCK_GUARD(&s->lock);
    memcpy(current, s->rem[index - 1], sizeof(current));
    iov[0] = (struct iovec){ .iov_base = current, .iov_len = sizeof(current) };
    iov[1] = (struct iovec){ .iov_base = value, .iov_len = sizeof(value) };
    if (!cca_sha256(iov, 2, s->rem[index - 1])) {
        warn_report("cca: failed to extend REM %" PRIu64 "; it is unchanged",
                    index);
        memcpy(s->rem[index - 1], current, sizeof(current));
        return RSI_ERROR_INPUT;
    }
    return RSI_SUCCESS;
}

/*
 * RSI_ATTESTATION_TOKEN_INIT takes the 64-byte challenge in x1-x8 and returns
 * an upper bound on the token size, which is what a guest sizes its buffer
 * against.  Any token part-way through being collected is abandoned: a guest
 * is allowed to restart, and a half-delivered token is not something to keep.
 */
static uint64_t cca_attest_token_init(ARMCPU *cpu, uint64_t *max_size)
{
    CcaTcgState *s = cca_get_state();

    QEMU_LOCK_GUARD(&s->lock);
    cca_token_discard(s);
    for (unsigned i = 0; i < CCA_CHALLENGE_LEN / 8; i++) {
        stq_le_p(s->challenge + i * 8, cpu->env.xregs[1 + i]);
    }
    s->token_requested = true;
    *max_size = RSI_TOKEN_MAX_SIZE;
    return RSI_SUCCESS;
}

/*
 * RSI_ATTESTATION_TOKEN_CONTINUE copies the next piece of the token into the
 * guest's buffer: x1 names a granule, x2 an offset inside it, x3 how much room
 * there is, and the reply says how much was written and whether more remains.
 *
 * The granule bound is enforced rather than clamped, because a real RMM
 * enforces it -- it writes into one delegated granule and cannot be asked to
 * cross into the next one.  A guest that computes the address and the offset
 * inconsistently is told so here instead of finding out on hardware.
 *
 * The first call after INIT builds the token and returns INCOMPLETE with
 * nothing written.  That is not an artefact: an RMM does a bounded amount of
 * work per call and signs the token across several of them, so a guest must
 * loop and must not treat a zero-length reply as failure.  Nowhere else can a
 * guest's collection loop be tested against that, so this reproduces it.
 */
static uint64_t cca_attest_token_continue(ARMCPU *cpu, uint64_t addr,
                                          uint64_t offset, uint64_t size,
                                          uint64_t *written)
{
    CcaTcgState *s = cca_get_state();
    size_t n;

    *written = 0;

    if (addr & (RSI_GRANULE_SIZE - 1)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_ATTESTATION_TOKEN_CONTINUE buffer 0x%" PRIx64
                      " is not granule-aligned\n", addr);
        return RSI_ERROR_INPUT;
    }
    if (size == 0 || offset >= RSI_GRANULE_SIZE ||
        offset + size > RSI_GRANULE_SIZE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_ATTESTATION_TOKEN_CONTINUE offset 0x%" PRIx64
                      " plus size 0x%" PRIx64 " leaves the granule\n",
                      offset, size);
        return RSI_ERROR_INPUT;
    }

    QEMU_LOCK_GUARD(&s->lock);

    if (!s->token_requested) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_ATTESTATION_TOKEN_CONTINUE with no token in "
                      "progress; RSI_ATTESTATION_TOKEN_INIT comes first\n");
        return RSI_ERROR_STATE;
    }

    if (!s->token) {
        s->token = cca_build_token(s->challenge, s->rim, s->rem);
        if (!s->token) {
            warn_report("cca: failed to build the attestation token");
            cca_token_discard(s);
            return RSI_ERROR_STATE;
        }
        warn_report_once("cca: produced a NON-GENUINE attestation token. Its "
                         "structure and measurements are real; every "
                         "signature and key in it is a fixed marker saying so. "
                         "It has no attestation meaning and must never be sent "
                         "to a relying party.");
        return RSI_INCOMPLETE;
    }

    n = MIN(size, s->token->len - s->token_off);
    if (address_space_write(arm_addressspace(CPU(cpu), MEMTXATTRS_UNSPECIFIED),
                            addr + offset, MEMTXATTRS_UNSPECIFIED,
                            s->token->data + s->token_off, n) != MEMTX_OK) {
        return RSI_ERROR_INPUT;
    }
    s->token_off += n;
    *written = n;

    if (s->token_off == s->token->len) {
        cca_token_discard(s);
        return RSI_SUCCESS;
    }
    return RSI_INCOMPLETE;
}

/*
 * RSI_IPA_STATE_GET reports the state of the range starting at @base: the
 * value, and how far it holds.  A guest uses it to discover what it was given
 * rather than to remember what it asked for, which is how Linux decides what
 * to accept at boot -- and it is the one RSI call a Linux Realm makes that
 * this emulation did not answer.
 *
 * The answer is a run, so this scans.  Sparse state means almost every scan
 * runs to the end of the range and finds RAM, which is the common case and the
 * cheapest one; the lock is taken once for the whole scan rather than per
 * granule, because a guest asking about its whole memory map at boot is
 * exactly what this is for.  Answering the entire range in one call is
 * permitted -- the reply is capped at @top, not at some quantum of work -- and
 * a guest is required to loop on it regardless.
 */
static uint64_t cca_ipa_state_get(ARMCPU *cpu, uint64_t base, uint64_t top,
                                  uint64_t *new_top, uint64_t *ripas)
{
    CcaTcgState *s = cca_get_state();
    uint64_t ipa;

    if ((base & (RSI_GRANULE_SIZE - 1)) || (top & (RSI_GRANULE_SIZE - 1)) ||
        top <= base) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: RSI_IPA_STATE_GET range 0x%" PRIx64 "-0x%" PRIx64
                      " is not a non-empty granule-aligned range\n", base, top);
        return RSI_ERROR_INPUT;
    }

    QEMU_LOCK_GUARD(&s->lock);
    *ripas = cca_ripas_get_locked(s, base);
    for (ipa = base + RSI_GRANULE_SIZE; ipa < top; ipa += RSI_GRANULE_SIZE) {
        if (cca_ripas_get_locked(s, ipa) != *ripas) {
            break;
        }
    }
    *new_top = ipa;
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

    case RSI_MEASUREMENT_READ:
        ret = cca_measurement_read(cpu, env->xregs[1]);
        break;

    case RSI_MEASUREMENT_EXTEND:
        ret = cca_measurement_extend(cpu, env->xregs[1], env->xregs[2]);
        break;

    case RSI_ATTESTATION_TOKEN_INIT: {
        uint64_t max_size = 0;

        ret = cca_attest_token_init(cpu, &max_size);
        env->xregs[1] = max_size;
        break;
    }

    case RSI_ATTESTATION_TOKEN_CONT: {
        uint64_t written = 0;

        ret = cca_attest_token_continue(cpu, env->xregs[1], env->xregs[2],
                                        env->xregs[3], &written);
        env->xregs[1] = written;
        break;
    }

    case RSI_IPA_STATE_GET: {
        uint64_t top = env->xregs[2];
        uint64_t ripas = RSI_RIPAS_RAM;

        ret = cca_ipa_state_get(cpu, env->xregs[1], env->xregs[2], &top,
                                &ripas);
        env->xregs[1] = top;
        env->xregs[2] = ripas;
        break;
    }

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
