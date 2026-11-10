/* Compile against the freshly generated header, never a hand-maintained copy. */
#include <stddef.h>
#include "c2pa.h"

typedef uint32_t (*trusted_revision_fn)(void);
typedef int64_t (*trusted_sign_fn)(
    struct C2paLiveVideoTrustedVsiSession *, const unsigned char *, uintptr_t, uint32_t,
    const unsigned char **);
typedef struct C2paLiveVideoTrustedVsiSession *(*trusted_create_fn)(
    struct C2paContext *, const char *, C2paSigningAlg, const unsigned char *, uintptr_t,
    const unsigned char *, uintptr_t, uint64_t, const char *, uint64_t, const char *, void *,
    C2paLiveVideoTrustedVsiSignCallbackV1);
typedef int64_t (*trusted_reserve_media_fn)(
    struct C2paLiveVideoTrustedVsiSession *, uint32_t, int64_t, uint32_t, uint32_t,
    const unsigned char **, struct C2paLiveVideoTrustedVsiSigningContextV1 *);
typedef int64_t (*trusted_bytes_in_out_fn)(
    struct C2paLiveVideoTrustedVsiSession *, const unsigned char *, uintptr_t,
    const unsigned char **);
typedef int64_t (*trusted_export_fn)(
    const struct C2paLiveVideoTrustedVsiSession *, const unsigned char **);
typedef int (*trusted_import_fn)(
    struct C2paLiveVideoTrustedVsiSession *, const unsigned char *, uintptr_t);
typedef int (*trusted_validate_fn)(uint32_t, C2paSigningAlg, const unsigned char *, uintptr_t);
typedef int64_t (*trusted_template_fn)(uint32_t, const unsigned char **);
typedef int (*trusted_preflight_fn)(
    const struct C2paLiveVideoTrustedVsiSession *, uint32_t, const unsigned char *, uintptr_t,
    uint32_t, int64_t, uint32_t, uint32_t, const char *);

#define ABI(fn, type) \
  _Static_assert(_Generic(&fn, type: 1, default: 0), #fn " ABI must match exactly")

ABI(c2pa_live_video_trusted_vsi_contract_revision, trusted_revision_fn);
ABI(c2pa_live_video_trusted_vsi_session_sign_sig_structure, trusted_sign_fn);
ABI(c2pa_live_video_trusted_vsi_session_create_callback_v1, trusted_create_fn);
ABI(c2pa_live_video_trusted_vsi_session_reserve_media_emsg, trusted_reserve_media_fn);
ABI(c2pa_live_video_trusted_vsi_session_finalize_init_uuid, trusted_bytes_in_out_fn);
ABI(c2pa_live_video_trusted_vsi_session_finalize_media_emsg, trusted_bytes_in_out_fn);
ABI(c2pa_live_video_trusted_vsi_session_export_state, trusted_export_fn);
ABI(c2pa_live_video_trusted_vsi_session_import_state, trusted_import_fn);
ABI(c2pa_live_video_trusted_vsi_validate_input, trusted_validate_fn);
ABI(c2pa_live_video_trusted_vsi_hash_template, trusted_template_fn);
ABI(c2pa_live_video_trusted_vsi_session_preflight, trusted_preflight_fn);

_Static_assert(sizeof(struct C2paLiveVideoTrustedVsiSigningContextV1) == 20,
               "V1 signing context size");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiSigningContextV1, sequence_number) == 4,
               "V1 sequence offset");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiSigningContextV1, has_event_id) == 16,
               "V1 event presence offset");
_Static_assert(sizeof(struct C2paLiveVideoTrustedVsiStatusV1) == 24, "V1 status size");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiStatusV1, blocked) == 18,
               "V1 status blocked offset");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiStatusV1, exhaustion_reason) == 20,
               "V1 status reason offset");
