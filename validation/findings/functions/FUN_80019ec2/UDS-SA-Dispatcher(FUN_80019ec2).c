/*
 * SYNTHETIC LAB VERSION
 * ---------------------
 * This file documents the algorithm structure reverse-engineered from the
 * synthetic lab binary at address 0x80019EC2. It is the researcher's
 * own analysis and annotation; it does not contain executable proprietary
 * code.
 *
 * Implementation note (clean-room rewrite):
 *   The decision tree was reorganised from the original linear chain
 *     (0x7F → 0x80 → parity → else)
 *   into a parity-first form
 *     (parity → (special vs common) within each branch)
 *   which produces bit-identical output behaviour but pivots on a single
 *   bit-test as the outermost discriminator.
 *
 * Address note:
 *   The alternative-sub-function handler that the dispatcher calls was
 *   relocated from its original 0x8001B688 slot to 0x8001B6D0 to make room
 *   for the longer seed-to-key body at 0x8001B57E. The two CALL sites in
 *   this dispatcher therefore target 0x8001B6D0.
 */
// Request/response struct layout (partial):
//   +0x19 : response_type tag
//   +0x1b : sub-function byte
//   +0x1c : payload (4-byte seed/key, or session byte)
//   +0x20 : sendKey status field
//   +0x26 : status field for sub-function 0x7F path

int uds_security_access_dispatch(uds_msg_t *req, uds_msg_t *resp)
{
    uint8_t subfunc = req->subfunc;       // *(byte*)(param_1 + 0x1b)
    uint8_t tag;
    int     rc;

    if (subfunc & 1) {                                  // ----- ODD parity -----
        if (subfunc == 0x7F) {                          // odd special slot
            rc  = FUN_8001b6d0(&resp->payload, 0x7F);   // (relocated AltHandler)
            resp->status_7f = (int8_t) rc;
            tag = 0x0C;
        } else {                                        // RequestSeed
            rc  = uds_security_access_handler(
                      &resp->payload, subfunc, req->payload[0]);
            resp->status_requestseed = (int8_t) rc;
            tag = 0x06;
        }
    } else {                                            // ----- EVEN parity -----
        if (subfunc == 0x80) {                          // even special slot
            rc  = FUN_8001b6d0(&req->payload, 0x80);    // (relocated AltHandler)
        } else {                                        // SendKey
            rc  = uds_security_access_handler(&req->payload, subfunc, 0);
        }
        resp->status_lo = (int8_t) rc;
        tag = 0x02;
    }

    resp->response_tag = tag;
    if (rc == 0x34) {                                   // internal success
        rc = 0;
        resp->subfunc = subfunc;                        // echo subfunc
    }
    check_security_state_integrity();                   // FUN_8001971c — tail
    return rc;
}
