/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "object_authorization.h"
#include "object_provider.h"

#include <assert.h>
#include <stdio.h>

static void test_unauthenticated_context(void) {
    file_object_authorization_context_t context;

    assert(fido_object_authorization_context_build(NULL, false, &context) == PICOKEYS_OK);
    assert(context.caller_namespace == FIDO_OBJECT_NAMESPACE);
    assert(context.session_epoch != 0);
    assert(context.facts_epoch == context.session_epoch);
    assert(context.facts == (FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND));
}

static void test_operation_evidence(void) {
    fido_object_authorization_evidence_t evidence = {
        .user_presence = true,
        .user_verification = true,
        .pin_uv_auth = false
    };
    file_object_authorization_context_t context;

    assert(fido_object_authorization_context_build(&evidence, false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_USER_PRESENCE) != 0);
    assert((context.facts & FILE_OBJECT_FACT_USER_VERIFICATION) != 0);
    assert((context.facts & FILE_OBJECT_FACT_APP_PIN) == 0);
}

static void test_pin_uv_auth_context(void) {
    fido_object_authorization_evidence_t evidence = {
        .user_presence = false,
        .user_verification = false,
        .pin_uv_auth = true
    };
    file_object_authorization_context_t context;

    assert(fido_object_authorization_context_build(&evidence, false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_APP_PIN) != 0);
    assert((context.facts & FILE_OBJECT_FACT_USER_VERIFICATION) != 0);
    assert((context.facts & FILE_OBJECT_FACT_USER_PRESENCE) == 0);
}

static void test_internal_context(void) {
    fido_object_authorization_evidence_t evidence = {
        .user_presence = true,
        .user_verification = true,
        .pin_uv_auth = true
    };
    file_object_authorization_context_t context;

    assert(fido_object_authorization_context_build(&evidence, true, &context) == PICOKEYS_OK);
    assert(context.facts == (FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND | FILE_OBJECT_FACT_INTERNAL_FIRMWARE));
}

static void test_epoch_invalidation(void) {
    file_object_authorization_context_t before;
    file_object_authorization_context_t after;

    assert(fido_object_authorization_context_build(NULL, false, &before) == PICOKEYS_OK);
    assert(fido_object_authorization_session_epoch() == before.session_epoch);
    fido_object_authorization_session_invalidate();
    assert(fido_object_authorization_context_build(NULL, false, &after) == PICOKEYS_OK);
    assert(after.session_epoch != before.session_epoch);
    assert(fido_object_authorization_session_epoch() == after.session_epoch);
    assert(after.facts_epoch == after.session_epoch);
}

int main(void) {
    test_unauthenticated_context();
    test_operation_evidence();
    test_pin_uv_auth_context();
    test_internal_context();
    test_epoch_invalidation();
    assert(fido_object_authorization_context_build(NULL, false, NULL) == PICOKEYS_ERR_NULL_PARAM);
    puts("fido_object_authorization_test: OK");
    return 0;
}
