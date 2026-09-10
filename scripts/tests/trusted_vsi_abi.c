/* Compile against the freshly generated header, never a hand-maintained copy. */
#include <stddef.h>
#include "c2pa.h"

typedef int64_t (*trusted_sign_fn)(
    struct C2paLiveVideoTrustedVsiSession *, const unsigned char *, uintptr_t,
    const unsigned char **, uint32_t *, uint32_t *, bool *);

_Static_assert(_Generic(&c2pa_live_video_trusted_vsi_session_sign_sig_structure,
                       trusted_sign_fn: 1, default: 0),
               "trusted expert signature ABI must match exactly");
_Static_assert(sizeof(struct C2paLiveVideoTrustedVsiSigningContextV1) == 20,
               "V1 signing context size");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiSigningContextV1, sequence_number) == 4,
               "V1 sequence offset");
_Static_assert(offsetof(struct C2paLiveVideoTrustedVsiSigningContextV1, has_event_id) == 16,
               "V1 event presence offset");
_Static_assert(sizeof(struct C2paLiveVideoTrustedVsiStatusV1) == 24,
               "V1 status size");
