# frozen_string_literal: true

require "test_helper"
require "rails/generators"
require_relative "../../lib/generators/authnz_eleven/authnz_eleven_generator"

# Predicate truth tables.
#
# Every `<% if … %>` in a template keys off one of these predicates, so the
# predicates *are* the logic. Pin them directly — flags in, boolean out — and
# every downstream branch is at least keyed correctly, which collapses the flag
# explosion into a few dozen assertions instead of 2^34 builds.
#
# Tier 1: constructs the generator and calls methods on it — no files generated,
# no app booted, no shell-out; a full pass is milliseconds. (The generator needs
# railties + activerecord merely to load, which is why the gemspec declares them.)
module AuthnzEleven
  # literal: ~40 predicates and their rows. The length is the specification;
  # splitting it to meet a line budget would scatter the truth tables without
  # making any of them clearer.
  class PredicatesTest < Minitest::Test
    # A minimal legal base: every build needs at least one sign-in door, or
    # validate_authentication_strategy! refuses it. Most rows below build on
    # one of these so they describe builds the generator would actually accept.
    DOOR = { password: true, email: "required" }.freeze

    # The validators that are pure functions of the flags. The other two
    # (validate_no_constant_collision!, validate_second_identity_namespaced!)
    # inspect the destination directory, so they're about disk state rather
    # than flag legality and have no place in a truth table.
    FLAG_VALIDATORS = %i[
      validate_principal!
      validate_authentication_strategy!
      validate_password_optional!
      validate_password_deferred!
      validate_email_option!
      validate_phone_option!
      validate_permanent!
      validate_contactable!
      validate_sms_code_option!
      validate_second_factor!
      validate_channel_dependencies!
    ].freeze

    # Truth tables as data. Each row is a flag set and the boolean the predicate
    # must return for it. Two annotations:
    #
    #   enabling: true  — the canonical minimal legal build that turns this
    #                     predicate on. Documents how to enable each predicate, and
    #                     is kept honest by the guards below (exactly one per
    #                     predicate, legal, minimal, actually enables). Minimal =
    #                     drop any flag and it goes false or illegal, except where a
    #                     larger set is needed to pin *which* route trips a compound
    #                     (see NON_MINIMAL_ENABLING_ROWS).
    #   note:           — why a row is interesting (an implication route, an
    #                     infeasible combination).
    #
    # Legality is computed by running FLAG_VALIDATORS (see #legal?), not
    # hand-tagged, because a predicate answers happily for flag sets the generator
    # rejects. The guard below makes sure no `enabling:` row inherits such a trap.
    TRUTH_TABLES = {
      # --- password machinery ------------------------------------------------
      # The headline compound: four different flags each imply a password.
      "password?" => {
        source: "options.password? || recoverable? || pwned? || strong_passwords? || password_rotatable?",
        rows: [
          { flags: {}, expect: false, note: "illegal on its own — no door at all" },
          { flags: DOOR, expect: true, enabling: true },
          { flags: { recoverable: true }, expect: true, note: "implied by --recoverable" },
          { flags: { pwned: true }, expect: true, note: "implied by --pwned" },
          { flags: { strong_passwords: true }, expect: true, note: "implied by --strong-passwords" },
          { flags: { password_rotatable: true }, expect: true, note: "implied by --password-rotatable" },
          { flags: { password_historical: true }, expect: true, note: "implied by --password-historical" }
        ]
      },
      "recoverable?" => {
        source: "options.recoverable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { recoverable: true, email: "required" }, expect: true, enabling: true }
        ]
      },
      "pwned?" => {
        source: "options.pwned?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { pwned: true, email: "required" }, expect: true, enabling: true }
        ]
      },
      "strong_passwords?" => {
        source: "options.strong_passwords?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { strong_passwords: true, email: "required" }, expect: true, enabling: true }
        ]
      },
      "password_rotatable?" => {
        source: "options.password_rotatable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password_rotatable: true, email: "required" }, expect: true, enabling: true,
            note: "implies --password, so it stands as a legal build on its own" }
        ]
      },
      "password_historical?" => {
        source: "options.password_historical?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password_historical: true, email: "required" }, expect: true, enabling: true,
            note: "implies --password, so it stands as a legal build on its own" }
        ]
      },

      # --- verification ------------------------------------------------------
      # One channel-agnostic opt-out flag (--no-verifiable), one predicate per
      # channel, each forced off by a build lacking that channel.
      "email_verifiable?" => {
        source: "options.verifiable? && !principals.email.nil?",
        rows: [
          { flags: DOOR, expect: true, enabling: true, note: "opt-OUT: on by default" },
          { flags: DOOR.merge(verifiable: false), expect: false },
          { flags: { passkey: true, username: true }, expect: false,
            note: "no channel to deliver to — forced false without --no-verifiable" },
          { flags: { email: "none" }, expect: false,
            note: "ILLEGAL set: none is no longer a valid mode; omission means absent" }
        ]
      },

      # The phone half of the same flag. Off unless a phone principal exists —
      # which is what keeps every pre-phone build free of the SMS machinery.
      "phone_verifiable?" => {
        source: "options.verifiable? && !principals.phone.nil?",
        rows: [
          { flags: DOOR, expect: false, note: "no phone principal, so nothing to verify" },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true,
            note: "opt-OUT like email: a phone principal verifies unless told not to" },
          { flags: DOOR.merge(phone: "optional"), expect: true,
            note: "requiredness is orthogonal — an optional number still verifies once set" },
          { flags: DOOR.merge(phone: "required", verifiable: false), expect: false,
            note: "the documented way to get a phone column without an SMS vendor" }
        ]
      },

      # --- encryption at rest ------------------------------------------------
      # One flag for every channel, because invitations.sent_to holds either one in a
      # single column and so admits no per-channel answer. The predicates stay per
      # channel anyway, which is what lets a template ask about a channel rather
      # than about the flag.
      "encrypted_pii?" => {
        source: "options.encrypted_pii?",
        rows: [
          { flags: DOOR, expect: false, note: "opt-IN: off by default" },
          { flags: DOOR.merge(encrypted_pii: true), expect: true, enabling: true }
        ]
      },

      "email_encrypted?" => {
        source: "options.encrypted_pii? && !principals.email.nil?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(encrypted_pii: true), expect: true, enabling: true },
          { flags: { passkey: true, username: true, encrypted_pii: true },
            expect: false, note: "no email column to encrypt" }
        ]
      },

      "phone_encrypted?" => {
        source: "options.encrypted_pii? && !principals.phone.nil?",
        rows: [
          { flags: DOOR.merge(encrypted_pii: true), expect: false,
            note: "no phone principal, so nothing to encrypt" },
          { flags: { password: true, phone: "required", encrypted_pii: true }, expect: true,
            enabling: true },
          { flags: DOOR.merge(phone: "required"), expect: false }
        ]
      },

      # ",permanent" removes the self-serve change surface for a channel. Two
      # predicates per channel: whether the /settings resource exists at all, and
      # whether the staged-change apparatus behind it does. The second is just the
      # first met with verification — a permanent build keeps the verification that
      # proves the value an account is BORN with, and drops only the change half.
      "email_changeable?" => {
        source: "!principals.email.nil? && principals.email.changeable?",
        rows: [
          { flags: DOOR, expect: true, enabling: true, note: "opt-OUT: changeable by default" },
          { flags: DOOR.merge(email: "required,permanent"), expect: false },
          { flags: DOOR.merge(email: "required,permanent", verifiable: false), expect: false,
            note: "warned about, not refused — nothing proved the address, so a typo is frozen" },
          { flags: { passkey: true, username: true }, expect: false,
            note: "no email column, so no form to remove" }
        ]
      },
      "email_change_verification?" => {
        source: "email_verifiable? && email_changeable?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(email: "required,permanent"), expect: false,
            note: "registration verification survives; only the staged CHANGE goes" },
          { flags: DOOR.merge(verifiable: false), expect: false,
            note: "the form stays, but the change lands unproved — nothing to stage" }
        ]
      },
      "phone_changeable?" => {
        source: "!principals.phone.nil? && principals.phone.changeable?",
        rows: [
          { flags: DOOR, expect: false, note: "no phone principal, so no form either way" },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(phone: "optional"), expect: true },
          { flags: DOOR.merge(phone: "required,permanent"), expect: false }
        ]
      },
      "phone_change_verification?" => {
        source: "phone_verifiable? && phone_changeable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(phone: "required,permanent"), expect: false },
          { flags: DOOR.merge(phone: "required", verifiable: false), expect: false }
        ]
      },

      # Whether the phone column is NULL-able. Requiredness decides it, except under
      # --guestable, where a *required* phone still has to allow nil because guests
      # carry no number and the constraint moves to the model validation.
      "phone_column_nullable?" => {
        source: "principals.phone&.then { |p| p.optional? || guestable? } || false",
        rows: [
          { flags: DOOR, expect: false, note: "no phone column at all" },
          { flags: DOOR.merge(phone: "required", registration: "closed"), expect: false },
          { flags: DOOR.merge(phone: "optional"), expect: true, enabling: true },
          { flags: DOOR.merge(phone: "required", guestable: true), expect: true,
            note: "guests carry a nil number, so NOT NULL would bar them" },
          { flags: DOOR.merge(phone: "required", registration: "open"), expect: false,
            note: "staged registration proves the number before account creation" },
          { flags: DOOR.merge(phone: "required", omniauth: true), expect: false,
            note: "a provider sign-up proves the number before the account exists too" }
        ]
      },

      # Whether an emailed link gates sign-up — and so everything that link touches:
      # the mailer method and view, the token purpose and expiry key, the "check
      # your email" page, and the controller that redeems it.
      "email_gated_registration?" => {
        source: "email_verifiable? && typed_staged_registration? && typed_sign_up_may_owe?(principals.email)",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false,
            note: "closed registration has nothing to gate" },
          { flags: { magic_link: true }, expect: false, note: "same: no sign-up" },
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(registration: "open", verifiable: false), expect: false,
            note: "no link is mailed, so there is nothing to wait for" },
          { flags: { password: true, phone: "required" }, expect: false,
            note: "no email column — the phone gate's page serves instead" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "required"), expect: true,
            note: "may or may not gate per request — the controller decides at runtime" },
          { flags: DOOR.merge(registration: "invite-only"), expect: false,
            note: "the only channel is the invited one, proved by clicking the invite" },
          { flags: DOOR.merge(registration: "invite-only", omniauth: true), expect: false,
            note: "same: the email is pinned to the invitation's" },
          { flags: DOOR.merge(registration: "invite-only", phone: "required"), expect: true,
            note: "invited by phone, the typed email still has to be proved" },
          { flags: { password: true, registration: "invite-only", phone: "required", email: "optional" }, expect: false,
            note: "an optional email is dropped from an invited sign-up, never gated" }
        ]
      },

      "typed_phone_gated_registration?" => {
        source: "phone_verifiable? && typed_staged_registration? && typed_sign_up_may_owe?(principals.phone)",
        rows: [
          { flags: DOOR.merge(registration: "open", phone: "required"), expect: true,
            note: "the phone is proved after the email and before account creation" },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(registration: "open", phone: "required", email: "optional"), expect: true,
            note: "may or may not gate per request — the controller decides at runtime" },
          { flags: DOOR.merge(registration: "invite-only", phone: "required", email: "optional"), expect: true,
            note: "invited by email, the typed number still has to be proved" },
          { flags: { password: true, phone: "required", registration: "invite-only" }, expect: false,
            note: "the only channel is the invited one, proved by clicking the invite" },
          { flags: DOOR.merge(phone: "required", username: true, registration: "closed"), expect: false,
            note: "closed registration has no sign-up" },
          { flags: DOOR.merge(registration: "open", phone: "required", verifiable: false),
            expect: false, note: "no SMS machinery, so nothing to gate with" }
        ]
      },

      "phone_gated_registration?" => {
        source: "typed_phone_gated_registration? || omniauth_registration_verifies_phone?",
        rows: [
          { flags: DOOR.merge(registration: "closed", phone: "required"), expect: false },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true,
            note: "the typed form gates" },
          { flags: DOOR.merge(registration: "invite-only", omniauth: true, phone: "required", email: "optional"),
            expect: true, note: "only the provider's profile form gates" }
        ]
      },

      "email_invitable?" => {
        source: "invitable? && !principals.email.nil?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(registration: "open-and-invites"), expect: true, enabling: true },
          { flags: { password: true, registration: "open-and-invites", phone: "required" }, expect: false }
        ]
      },
      "phone_invitable?" => {
        source: "invitable? && !principals.phone.nil?",
        rows: [
          { flags: DOOR.merge(registration: "open-and-invites"), expect: false },
          { flags: { password: true, registration: "open-and-invites", phone: "required" },
            expect: true, enabling: true }
        ]
      },
      "multi_channel_invitable?" => {
        source: "email_invitable? && phone_invitable?",
        rows: [
          { flags: DOOR.merge(registration: "open-and-invites"), expect: false },
          { flags: DOOR.merge(registration: "open-and-invites", phone: "required"), expect: true, enabling: true },
          { flags: { password: true, registration: "open-and-invites", phone: "required" }, expect: false }
        ]
      },
      "phone_registration_claim?" => {
        source: "phone_gated_registration? || (pending_registration? && phone_invitable?)",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password: true, phone: "required" }, expect: true,
            enabling: true, note: "ordinary phone-gated registration needs the claim" },
          { flags: DOOR.merge(registration: "open-and-invites", phone: "required"), expect: true,
            note: "required email normally gates sign-up, but a phone invitation proves phone instead" },
          { flags: DOOR.merge(registration: "invite-only", phone: "required"), expect: true,
            note: "invite-only stages too, and an email invitee's typed number needs the claim" }
        ]
      },

      # Cache-backed SMS challenges. Invitations deliberately do not widen this:
      # a signed invitation link has no code or guess budget.
      "sms?" => {
        source: "phone_verifiable? || sms_code?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(phone: "required", verifiable: false), expect: false,
            note: "nothing sends a text, so no seam, no job, no cache-backed challenge" },
          { flags: { sms_code: true, verifiable: false }, expect: true,
            note: "the door still texts codes with verification switched off" }
        ]
      },

      "sms_delivery?" => {
        source: "sms? || phone_invitable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(registration: "open-and-invites", phone: "required", verifiable: false), expect: true,
            note: "a phone invitation needs delivery without challenge machinery" },
          { flags: DOOR.merge(phone: "required", verifiable: false), expect: false }
        ]
      },

      # The passwordless SMS door — the phone sibling of --magic-link.
      "sms_code?" => {
        source: "options.sms_code?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { sms_code: true, phone: "required" }, expect: true, enabling: true,
            note: "a door on its own — no --password needed, but its phone is explicit" },
          { flags: DOOR.merge(sms_code: true, phone: "optional"), expect: true,
            note: "optional phone is fine once another door covers the numberless accounts" },
          { flags: { sms_code: true, phone: "optional" }, expect: true,
            note: "ILLEGAL: sole door with accounts that may have no number to text" }
        ]
      },

      # Off by default: an honest build reveals whether an address is registered.
      "coy?" => {
        source: "options.coy?",
        rows: [
          { flags: DOOR, expect: false, note: "opt-IN: off by default" },
          { flags: DOOR.merge(coy: true), expect: true, enabling: true }
        ]
      },

      # --- second factor vs. passwordless door -------------------------------
      "second_factor?" => {
        source: "second_factors.any?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(second_factor: "totp"), expect: true, enabling: true },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: true,
            note: "security keys alone are a second factor now — no TOTP dragged in" }
        ]
      },
      "totp?" => {
        source: "second_factors.include?(:totp)",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(second_factor: "totp"), expect: true, enabling: true },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: false,
            note: "the whole point of the split: no totp_secret column here" },
          { flags: DOOR.merge(second_factor: "totp,webauthn"), expect: true }
        ]
      },
      "security_keys?" => {
        source: "second_factors.include?(:webauthn)",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: true, enabling: true },
          { flags: DOOR.merge(second_factor: "totp"), expect: false },
          { flags: DOOR.merge(second_factor: "totp,webauthn"), expect: true }
        ]
      },
      "sms_second_factor?" => {
        source: "second_factors.include?(:sms)",
        rows: [
          { flags: DOOR.merge(phone: "required"), expect: false },
          { flags: { password: true, phone: "required", second_factor: "sms" }, expect: true, enabling: true },
          { flags: DOOR.merge(phone: "required", second_factor: "totp"), expect: false },
          { flags: DOOR.merge(phone: "required", second_factor: "totp,sms"), expect: true }
        ]
      },
      "multiple_second_factors?" => {
        source: "second_factors.size > 1",
        rows: [
          { flags: DOOR.merge(second_factor: "totp"), expect: false },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: false },
          { flags: DOOR.merge(second_factor: "totp,webauthn"), expect: true, enabling: true,
            note: "only here must a sign-in choose a challenge, and the pages cross-link" },
          { flags: DOOR.merge(phone: "required", second_factor: "totp,sms"), expect: true }
        ]
      },
      "both_second_factors?" => {
        source: "totp? && security_keys?",
        rows: [
          { flags: DOOR.merge(second_factor: "totp"), expect: false },
          { flags: DOOR.merge(phone: "required", second_factor: "totp,sms"), expect: false,
            note: "the emitted tests this gates drive an authenticator against a security key" },
          { flags: DOOR.merge(second_factor: "totp,webauthn"), expect: true, enabling: true }
        ]
      },
      "passkey?" => {
        source: "options.passkey?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { passkey: true, email: "required" }, expect: true, enabling: true, note: "a door in its own right" }
        ]
      },
      "webauthn_credentials?" => {
        source: "security_keys? || passkey?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: true, enabling: true },
          { flags: { passkey: true }, expect: true, note: "the other role of the shared table" }
        ]
      },
      "passkey_and_security_keys?" => {
        source: "passkey? && security_keys?",
        rows: [
          { flags: { passkey: true }, expect: false },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: false },
          { flags: { passkey: true, second_factor: "webauthn", email: "required" }, expect: true, enabling: true,
            note: "only here must the shared table tell the two roles apart" }
        ]
      },
      "typed_registration_guarantees_sign_in_method?" => {
        source: "required password or a required channel-backed door",
        rows: [
          { flags: { passkey: true, email: "required" }, expect: false },
          { flags: DOOR, expect: true, enabling: true },
          { flags: { magic_link: true, email: "required" }, expect: true },
          { flags: { sms_code: true, phone: "required" }, expect: true },
          { flags: { password: "optional", email: "required" }, expect: false }
        ]
      },
      "credential_staged_registration?" => {
        source: "typed_registration? && !typed_registration_guarantees_sign_in_method?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { passkey: true, email: "required" }, expect: true, enabling: true },
          { flags: { password: "optional", email: "required" }, expect: true },
          { flags: { password: "deferred", magic_link: true, email: "required" }, expect: false },
          { flags: { magic_link: true, passkey: true, username: true, email: "optional", contactable: false },
            expect: true }
        ]
      },
      "pre_account_password_enrollment?" => {
        source: "credential_staged_registration? && password?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { password: "deferred", email: "required" }, expect: true, enabling: true },
          { flags: { passkey: true, email: "required" }, expect: false }
        ]
      },
      "pre_account_passkey_enrollment?" => {
        source: "credential_staged_registration? && passkey?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { passkey: true, email: "required" }, expect: true, enabling: true },
          { flags: { password: "deferred", email: "required" }, expect: false }
        ]
      },
      # Whether an invitation to this channel mints the account at the sign-up POST.
      # The invitation proves its own channel; a SECOND channel the build requires
      # is still unproved, so it holds the registration open.
      "email_invitation_completes_registration?" => {
        source: "invited_registration_completes?(:email)",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: { password: true, registration: "open-and-invites", email: "optional", phone: "required" },
            expect: false, note: "the required phone beside it is still unproved" },
          { flags: { password: true, registration: "open-and-invites", email: "required", phone: "optional" },
            expect: true },
          { flags: { password: true, registration: "invite-only", email: "optional", phone: "required" },
            expect: false, note: "invite-only stages like open: the required phone is still unproved" },
          { flags: { passkey: true, registration: "open-and-invites", email: "required" },
            expect: false, note: "the form leaves the row with no way to sign in" },
          { flags: { magic_link: true, passkey: true, username: true, registration: "open-and-invites",
                     email: "optional", phone: "optional" },
            expect: true, note: "the magic link signs in with the invited address" }
        ]
      },
      "phone_invitation_completes_registration?" => {
        source: "invited_registration_completes?(:phone)",
        rows: [
          { flags: { password: true, phone: "required" }, expect: true, enabling: true },
          { flags: { password: true, registration: "open-and-invites", email: "required", phone: "optional" },
            expect: false, note: "the required email beside it is still unproved" },
          { flags: { password: true, registration: "open-and-invites", email: "optional", phone: "required" },
            expect: true },
          { flags: { passkey: true, registration: "open-and-invites", phone: "required" },
            expect: false, note: "the form leaves the row with no way to sign in" }
        ]
      },
      "sign_up_fixture_can_sign_in?" => {
        source: "password_required? || magic_link? || sms_code?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: { passkey: true, email: "required" }, expect: false },
          { flags: { password: "optional", email: "required" }, expect: false },
          { flags: { magic_link: true, passkey: true, username: true, email: "optional" }, expect: true,
            note: "the build guarantees nothing, but the fixture's email is a way in" }
        ]
      },
      # The gate's last resort. A provider is not one of the options offered
      # alongside others — reaching the gate means the typed route was taken, so
      # the button was already declined on the sign-up form — but a build with no
      # password and no passkey has nothing else to put there, and the account does
      # not exist yet, so /settings is not reachable either.
      "pre_account_provider_enrollment?" => {
        source: "credential_staged_registration? && omniauth? && registration_credential_options.empty?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { omniauth: true, sms_code: true, phone: "optional", email: "required" },
            expect: true, enabling: true },
          { flags: { password: "optional", omniauth: true, email: "required" }, expect: false },
          { flags: { passkey: true, omniauth: true, email: "required" }, expect: false },
          { flags: { password: true, omniauth: true, email: "required" }, expect: false }
        ]
      },
      # Whether the hold gets a page of its own to ask on, which needs an actual
      # choice to put there. A provider is never one of the options — reaching the
      # hold means the typed route was taken, so the provider button was already
      # declined — which is why --passkey --omniauth is false here and still lands
      # on the passkey page directly.
      "registration_credential_chooser?" => {
        source: "registration_credential_options.size > 1",
        rows: [
          { flags: { password: "deferred", passkey: true, email: "required" }, expect: true, enabling: true },
          { flags: { password: "deferred", passkey: true, omniauth: true, email: "required" }, expect: true },
          { flags: { passkey: true, omniauth: true, email: "required" }, expect: false },
          { flags: { password: "deferred", email: "required" }, expect: false },
          { flags: { passkey: true, email: "required" }, expect: false },
          { flags: { password: "deferred", passkey: true, magic_link: true, email: "required" }, expect: false },
          { flags: DOOR, expect: false }
        ]
      },

      # --- other doors -------------------------------------------------------
      "magic_link?" => {
        source: "options.magic_link?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { magic_link: true, email: "required" }, expect: true, enabling: true,
            note: "a door in its own right" }
        ]
      },
      "omniauth?" => {
        source: "options.omniauth?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { omniauth: true, email: "required" }, expect: true, enabling: true,
            note: "a door in its own right" }
        ]
      },
      # Whether a hermetic test can perform this build's sign-in gesture. Passkey and
      # omniauth can't be driven, so those builds get a minted session instead — fine
      # for tests about the signed-in area, not for tests about signing in itself.
      "test_drivable_door?" => {
        source: "password? || magic_link? || sms_code?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: { magic_link: true }, expect: true, note: "an emailed link is a GET a test can make" },
          { flags: { sms_code: true }, expect: true,
            note: "the code is readable out of the enqueued text" },
          { flags: { passkey: true }, expect: false,
            note: "needs a WebAuthn authenticator" },
          { flags: { omniauth: true }, expect: false,
            note: "needs a provider round-trip" }
        ]
      },
      "omniauth_registration?" => {
        source: "omniauth? && omniauth_registration_principals.any?",
        rows: [
          { flags: { omniauth: true }, expect: false,
            note: "a provider supplies email, so nothing is missing" },
          { flags: { omniauth: true, username: true }, expect: true, enabling: true,
            note: "a provider never supplies a username — hence the interstitial" },
          { flags: DOOR.merge(username: true), expect: false, note: "no omniauth, no registration form" },
          { flags: DOOR.merge(omniauth: true, phone: "required"), expect: true,
            note: "the form collects the number, which is then proved before the account exists" },
          { flags: DOOR.merge(omniauth: true, phone: "optional"), expect: false,
            note: "an optional number isn't asked for" }
        ]
      },

      # --- login keys --------------------------------------------------------
      "multi_login?" => {
        source: "principals.multi_login?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(username: true), expect: true, enabling: true },
          { flags: { passkey: true, username: true }, expect: false,
            note: "username is the only login key once email is gone" }
        ]
      },

      # --- session policy ----------------------------------------------------
      "rememberable?" => {
        source: "options.rememberable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(rememberable: true), expect: true, enabling: true }
        ]
      },
      "timeoutable?" => {
        source: "options.timeoutable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(timeoutable: true), expect: true, enabling: true }
        ]
      },
      "max_sessionable?" => {
        source: "options.max_sessionable.present?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(max_sessionable: "evict"), expect: true, enabling: true },
          { flags: DOOR.merge(max_sessionable: "prompt"), expect: true,
            note: "either strategy value turns the cap on" }
        ]
      },
      "max_sessions_evict?" => {
        source: 'max_sessionable? && options.max_sessionable == "evict"',
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(max_sessionable: "evict"), expect: true, enabling: true },
          { flags: DOOR.merge(max_sessionable: "prompt"), expect: false, note: "the other strategy" }
        ]
      },
      "max_sessions_prompt?" => {
        source: 'max_sessionable? && options.max_sessionable == "prompt"',
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(max_sessionable: "prompt"), expect: true, enabling: true },
          { flags: DOOR.merge(max_sessionable: "evict"), expect: false, note: "the default strategy" }
        ]
      },
      "trackable?" => {
        source: "options.trackable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(trackable: true), expect: true, enabling: true }
        ]
      },
      "last_seenable?" => {
        source: "options.last_seenable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(last_seenable: true), expect: true, enabling: true }
        ]
      },
      "security_notifications?" => {
        source: "options.security_notifications?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(security_notifications: true), expect: true, enabling: true }
        ]
      },
      "api_tokens?" => {
        source: "options.api_tokens?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(api_tokens: true), expect: true, enabling: true }
        ]
      },

      # --- registration ------------------------------------------------------
      # A typed sign-up FORM, not "accounts can be created" — the omniauth callback
      # registers with no form at all (pending_registration? asks that).
      "typed_registration?" => {
        source: "registration != closed && !social_login_only?",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true, note: "open by default" },
          { flags: DOOR.merge(registration: "open-and-invites"), expect: true },
          { flags: DOOR.merge(registration: "invite-only"), expect: true },
          { flags: { omniauth: true, registration: "open" }, expect: false,
            note: "a provider is the only door, so the form would collect an address " \
                  "the provider supplies anyway and end at 'now connect an account'" },
          { flags: { omniauth: true, registration: "open-and-invites" }, expect: false,
            note: "same — an invitee clicks the provider button with the right account" },
          { flags: DOOR.merge(omniauth: true, registration: "open"), expect: true,
            note: "a password is a door the form CAN establish, so it earns its place" }
        ]
      },

      "social_login_only?" => {
        source: "omniauth? && !password? && !passkey? && !magic_link? && !sms_code?",
        rows: [
          { flags: { omniauth: true, email: "required" }, expect: true, enabling: true },
          { flags: DOOR.merge(omniauth: true), expect: false, note: "a password can be typed" },
          { flags: { omniauth: true, passkey: true }, expect: false,
            note: "a passkey build's form is the only way to make an account at all" },
          { flags: { omniauth: true, magic_link: true }, expect: false },
          { flags: DOOR, expect: false, note: "no provider" }
        ]
      },
      "public_registration?" => {
        source: "typed_registration? && !invite_only?",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true, note: "open by default" },
          { flags: DOOR.merge(registration: "invite-only"), expect: false,
            note: "registration exists but is not public — login page must not link to it" }
        ]
      },
      "invitable?" => {
        source: "registration is open-and-invites or invite-only",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(registration: "open-and-invites"), expect: true, enabling: true },
          { flags: DOOR.merge(registration: "invite-only"), expect: true,
            note: "the invite-only mode includes invitations" }
        ]
      },
      "invite_only?" => {
        source: "registration == invite-only",
        rows: [
          { flags: DOOR.merge(registration: "open-and-invites"), expect: false },
          { flags: DOOR.merge(registration: "invite-only"), expect: true, enabling: true }
        ]
      },
      "guestable?" => {
        source: "options.guestable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(guestable: true), expect: true, enabling: true }
        ]
      },
      "captchable?" => {
        source: "options.captchable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(captchable: true), expect: true, enabling: true }
        ]
      },
      "easy_dev_login?" => {
        source: "options.easy_dev_login?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(easy_dev_login: true), expect: true, enabling: true }
        ]
      },

      # --- teams -------------------------------------------------------------
      "teams?" => {
        source: "options[:teams].present?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(teams: "session"), expect: true, enabling: true },
          { flags: DOOR.merge(teams: "scope"), expect: true }
        ]
      },
      "scope_teams?" => {
        source: "options[:teams] == scope",
        rows: [
          { flags: DOOR.merge(teams: "session"), expect: false },
          { flags: DOOR.merge(teams: "scope"), expect: true, enabling: true }
        ]
      },
      "middleware_teams?" => {
        source: "options[:teams] == middleware",
        rows: [
          { flags: DOOR.merge(teams: "scope"), expect: false },
          { flags: DOOR.merge(teams: "middleware"), expect: true, enabling: true }
        ]
      },
      "session_carries_team?" => {
        source: "options[:teams] == session",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(teams: "session"), expect: true, enabling: true },
          { flags: DOOR.merge(teams: "scope"), expect: false,
            note: "the path is the source of truth there, not the session" }
        ]
      },

      # --- sudo --------------------------------------------------------------
      "sudoable?" => {
        source: "options.sudoable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(sudoable: true), expect: true, enabling: true }
        ]
      },
      "fail_open_sudo?" => {
        source: "sudoable? && passwordless_account_possible?",
        rows: [
          { flags: DOOR.merge(sudoable: true), expect: false,
            note: "a pure password build can always pose a bar" },
          { flags: DOOR.merge(sudoable: true, omniauth: true), expect: true, enabling: true,
            note: "an omniauth-only user has no password to re-prove" },
          { flags: { password: "optional", passkey: true, sudoable: true }, expect: true,
            note: "left the field blank, never enrolled a passkey" },
          { flags: { password: "deferred", passkey: true, sudoable: true }, expect: true,
            note: "the same account, before it sets a password" },
          { flags: { magic_link: true, second_factor: "totp", sudoable: true }, expect: true,
            note: "passwordless build — an account that never enrolled has nothing to re-prove" },
          { flags: DOOR, expect: false }
        ]
      },
      # One bar, posed to everyone, so which bar to pose is known at generation time
      # and the whole dispatch (plus its helper_method) is emitted away.
      "single_sudo_bar?" => {
        source: "sudo_bars == [ :password ] && unconditional_password_bar?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(second_factor: "totp"), expect: true,
            note: "the password bar is unconditional, so :totp can never be chosen and drops out" },
          { flags: DOOR.merge(second_factor: "webauthn"), expect: false,
            note: "a security key holder gets that bar instead" },
          { flags: DOOR.merge(omniauth: true), expect: false,
            note: "an omniauth account has no password it chose, so the bar is conditional" },
          { flags: { passkey: true }, expect: false, note: "one bar, but it falls through to :open" }
        ]
      },
      # Which builds have a credential a settings page can remove one of at a time.
      # NOT whether removing one would lock the account — that is a fact about the
      # account, answered at runtime by the model's #last_sign_in_method?. Two
      # generation-time predicates used to answer it (passkey_only_door?,
      # omniauth_only_door?); each excluded the other, so a build with both doors
      # emitted neither guard.
      "removable_credentials?" => {
        source: "passkey? || omniauth? || password_removable?",
        rows: [
          { flags: { passkey: true, email: "required" }, expect: true, enabling: true },
          { flags: { omniauth: true }, expect: true },
          { flags: { passkey: true, omniauth: true }, expect: true,
            note: "the build that used to fall between the two old door predicates" },
          { flags: { password: "optional", magic_link: true }, expect: true,
            note: "no passkey and no provider, but the form called the password optional" },
          { flags: DOOR.merge(magic_link: true), expect: false,
            note: "another door exists, but the form still requires a password and offers no way out of it" },
          { flags: DOOR, expect: false,
            note: "the only door is the password, so nothing here can be given up" },
          { flags: { magic_link: true }, expect: false,
            note: "an address is changed, never removed" }
        ]
      },
      # What the SIGN-UP FORM does about a password. A build fact, and only about
      # the form — which accounts end up holding one is answered per row.
      # Whether the password is enrolled after the account exists instead of typed
      # on the way in. The only credential in this gem with a choice about when: a
      # passkey is always enrolled afterwards, a provider ceremony IS the arrival,
      # and a magic link or SMS code is not enrolled at all.
      "password_deferred?" => {
        source: %(password? && options[:password] == "deferred"),
        rows: [
          { flags: { password: "deferred", email: "required" }, expect: true, enabling: true },
          { flags: { password: "optional", omniauth: true }, expect: false },
          { flags: DOOR, expect: false },
          { flags: { passkey: true }, expect: false, note: "no password door at all" }
        ]
      },
      # What password? meant everywhere before --password=deferred existed. Sites
      # that care about the FORM ask this; sites that care about the BUILD keep
      # asking password?.
      "password_on_sign_up_form?" => {
        source: "password? && !password_deferred?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: { password: "optional", passkey: true }, expect: true,
            note: "the field is there, it may just be left blank" },
          { flags: { password: "deferred" }, expect: false },
          { flags: { passkey: true }, expect: false }
        ]
      },
      "password_form_optional?" => {
        source: %(password? && options[:password] == "optional"),
        rows: [
          { flags: { password: "optional", omniauth: true, email: "required" }, expect: true, enabling: true },
          { flags: { password: "optional", passkey: true }, expect: true },
          { flags: DOOR.merge(omniauth: true), expect: false,
            note: "another door exists, but nobody asked for the field to be skippable" },
          { flags: DOOR, expect: false },
          { flags: { omniauth: true }, expect: false, note: "no password door at all" }
        ]
      },
      # Whether ANY path here can mint an account with no password on file: the
      # condition on the nullable column, on lifting the presence rule from a row,
      # and on the settings page offering to set a first one.
      #
      # Not "does another door exist" — that was the old password_optional?, which
      # answered a question about which BUILDS have a second door to a question
      # about which ROWS may lack a password. A --password --passkey build still
      # collects a password from everyone who signs up.
      "password_nullable?" => {
        source: "password? && (password_form_optional? || password_deferred? || omniauth? || guestable?)",
        rows: [
          { flags: DOOR.merge(omniauth: true), expect: true, enabling: true,
            note: "the provider callback mints accounts no form ever touched" },
          { flags: DOOR.merge(guestable: true), expect: true,
            note: "a guest is a real row and is never signed into" },
          { flags: { password: "optional", passkey: true }, expect: true },
          { flags: { password: "deferred" }, expect: true,
            note: "no field on the form, so no row it mints has a digest" },
          { flags: DOOR.merge(passkey: true), expect: false,
            note: "the passkey is an addition to a password everyone was made to choose" },
          { flags: DOOR.merge(magic_link: true), expect: false },
          { flags: DOOR, expect: false },
          { flags: { omniauth: true }, expect: false, note: "no password door at all" }
        ]
      },
      # Whether settings offers to REMOVE a password: only where the form called it
      # optional on the way in. Setting a first one is a different question
      # (password_nullable?), and a required build still needs that half.
      "password_removable?" => {
        source: "password_form_optional? || password_deferred?",
        rows: [
          { flags: { password: "optional", omniauth: true, email: "required" }, expect: true, enabling: true },
          { flags: { password: "deferred" }, expect: true,
            note: "never made to set one, so never trapped with one" },
          { flags: DOOR.merge(omniauth: true), expect: false,
            note: "a provider account may SET a password here; nobody may give one up" },
          { flags: DOOR, expect: false }
        ]
      },
      # Whether EVERY row may lack a password, on every model including the policy.
      # Where it holds, #password_may_be_blank? would answer a constant true on both
      # User and PendingRegistration, so PasswordPolicy drops the presence error
      # flatly and neither model generates the predicate at all.
      #
      # Shares an expression with password_removable? and asks a different question:
      # that one is whether settings offers a door OUT of a password, this one is
      # which rows are excused having one. They coincide because a form that let you
      # decline is also the only form that lets you give one up.
      "password_blank_rows_all?" => {
        source: "password_form_optional? || password_deferred?",
        rows: [
          { flags: { password: "optional", omniauth: true, email: "required" }, expect: true, enabling: true,
            note: "the form let everyone decline, so no row is excused more than another" },
          { flags: { password: "deferred" }, expect: true,
            note: "no field on the form at all" },
          { flags: DOOR.merge(omniauth: true), expect: false,
            note: "provider rows are excused and the form's rows are not — the seam earns its keep" },
          { flags: DOOR.merge(guestable: true), expect: false,
            note: "only guests are excused" },
          { flags: DOOR, expect: false,
            note: "no row may lack one, so the question is never asked" }
        ]
      },
      # Whether a guest is excused the phone-presence rule, which is the only shared
      # validation that asks a row whether it is a guest — and therefore the only
      # reason PendingRegistration defines `guest? = false`.
      #
      # The format rule is not a reason: allow_blank already skips the nil phone every
      # guest carries, so `unless: :guest?` there changed nothing.
      "guest_excused_from_phone?" => {
        rows: [
          { flags: { password: true, guestable: true, phone: "required" }, expect: true, enabling: true,
            note: "a presence rule with no hold behind it, and guests carry no number" },
          { flags: DOOR.merge(guestable: true, phone: "required", registration: "open"), expect: true,
            note: "guest rows remain the intentional nil-phone exception" },
          { flags: DOOR.merge(guestable: true, phone: "optional"), expect: false,
            note: "an optional phone has no presence rule at all" },
          { flags: DOOR.merge(guestable: true), expect: false, note: "no phone principal" },
          { flags: DOOR.merge(phone: "required"), expect: false, note: "no guests" }
        ]
      },
      # Whether the password bar, when this build has one, applies to every account —
      # which makes it terminal in sudo_strategy and drops :totp out of the emitted
      # code. Wrong here is a lockout: an account the bar doesn't fit is posed one it
      # cannot answer.
      "unconditional_password_bar?" => {
        source: "password? && !passwordless_account_possible?",
        rows: [
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(omniauth: true), expect: false,
            note: "an omniauth account has a password it never chose, so the bar is conditional " \
                  "and :totp below it becomes reachable" },
          { flags: { password: "optional", passkey: true }, expect: false,
            note: "the form let the field be blank" },
          { flags: { password: "deferred", passkey: true }, expect: false,
            note: "no password until the account sets one, and it may enroll a passkey instead" },
          { flags: { magic_link: true }, expect: false, note: "no password bar at all" },
          { flags: { passkey: true, second_factor: "totp" }, expect: false }
        ]
      },

      # --- deadbolt -----------------------------------------------------------
      "deadboltable?" => {
        source: "options.deadboltable? && password?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(deadboltable: true), expect: true, enabling: true },
          { flags: { passkey: true, deadboltable: true }, expect: false,
            note: "no guessable secret to count guesses against; validate_deadboltable! refuses this pairing" },
          { flags: { recoverable: true, deadboltable: true }, expect: true,
            note: "via password?'s implication route" }
        ]
      },
      "bannable?" => {
        source: "options.bannable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(bannable: true), expect: true, enabling: true },
          { flags: { passkey: true, bannable: true }, expect: true,
            note: "a suspension is orthogonal to how the account signs in" }
        ]
      },

      # --- admin -------------------------------------------------------------
      "adminable?" => {
        source: "options.adminable? || admin_dashboard? || impersonatable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(adminable: true), expect: true, enabling: true },
          { flags: DOOR.merge(admin_dashboard: true), expect: true, note: "implied by --admin-dashboard" },
          { flags: DOOR.merge(impersonatable: true), expect: true, note: "implied by --impersonatable" }
        ]
      },
      "admin_dashboard?" => {
        source: "options.admin_dashboard?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(admin_dashboard: true), expect: true, enabling: true }
        ]
      },
      "impersonatable?" => {
        source: "options.impersonatable?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(impersonatable: true), expect: true, enabling: true }
        ]
      },
      "admin_mfa_gate?" => {
        source: "admin_dashboard? && second_factor?",
        rows: [
          { flags: DOOR.merge(admin_dashboard: true), expect: false },
          { flags: DOOR.merge(second_factor: "totp"), expect: false },
          { flags: DOOR.merge(admin_dashboard: true, second_factor: "totp"), expect: true, enabling: true }
        ]
      },
      "impeded?" => {
        source: "impediments.any?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: { passkey: true, email: "required" }, expect: false,
            note: "initial passkey enrollment happens before the account exists" },
          { flags: DOOR.merge(admin_dashboard: true, second_factor: "totp"), expect: true, enabling: true,
            note: "via admin_mfa_gate?" },
          { flags: DOOR.merge(max_sessionable: "prompt"), expect: true, note: "via max_sessions_prompt?" },
          { flags: DOOR.merge(password_rotatable: true), expect: true, note: "via password_rotatable?" },
          { flags: DOOR.merge(registration: "open", phone: "required"), expect: false,
            note: "registration proves the number before creating the account" }
        ]
      },
      # --- staged registration -----------------------------------------------

      "channel_staged_registration?" => {
        source: "typed_registration? && (email_verifiable? || phone_verifiable?)",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(verifiable: false), expect: false },
          { flags: DOOR.merge(registration: "invite-only"), expect: true,
            note: "invite-only stages like open: the invitation proves only its own channel" }
        ]
      },
      "typed_staged_registration?" => {
        source: "typed_registration? && (channel_staged_registration? || credential_staged_registration?)",
        rows: [
          { flags: { omniauth: true, email: "required", registration: "open" }, expect: false,
            note: "a provider-only build has no typed form to stage" },
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true },
          { flags: { password: true, email: "required", registration: "invite-only" }, expect: true,
            note: "staged, though the invitation proves the only channel so it completes at once" },
          { flags: { omniauth: true, username: true }, expect: false,
            note: "only the provider sign-up stages; there is no typed form" }
        ]
      },
      "pending_registration_model?" => {
        source: "typed_staged_registration? || omniauth_registration?",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(verifiable: false), expect: false },
          { flags: { passkey: true, email: "required", registration: "invite-only" }, expect: true },
          { flags: { password: true, email: "required", registration: "invite-only" }, expect: true },
          { flags: { omniauth: true, username: true }, expect: true,
            note: "a provider sign-up still owes its username, so it is staged" },
          { flags: { omniauth: true, email: "required" }, expect: false,
            note: "the provider supplies everything, so the callback creates the account" }
        ]
      },

      # A provider sign-up's form collects a number, which a texted code proves
      # before the account exists.
      "omniauth_registration_verifies_phone?" => {
        source: "omniauth_registration_collects_phone? && phone_verifiable?",
        rows: [
          { flags: { omniauth: true, username: true }, expect: false, note: "no phone" },
          { flags: { omniauth: true, phone: "required" }, expect: true, enabling: true },
          { flags: { omniauth: true, phone: "optional" }, expect: false,
            note: "an optional number isn't asked for" },
          { flags: { omniauth: true, phone: "required", verifiable: false }, expect: false,
            note: "nothing proves it; the form's number is taken as typed" }
        ]
      },

      # Where the row carries a provider login.
      "pending_registration_holds_provider?" => {
        source: "omniauth_registration? || pre_account_provider_enrollment?",
        rows: [
          { flags: DOOR, expect: false, note: "no provider" },
          { flags: { omniauth: true, username: true }, expect: true, enabling: true,
            note: "the provider sign-up is the row" },
          { flags: { omniauth: true, email: "required" }, expect: false,
            note: "nothing owed, so no row" }
        ]
      },
      "pending_registration?" => {
        source: "pending_registration_model? (compatibility alias)",
        rows: [
          { flags: DOOR.merge(registration: "closed"), expect: false },
          { flags: DOOR, expect: true, enabling: true },
          { flags: DOOR.merge(verifiable: false), expect: false },
          { flags: { passkey: true, email: "required", registration: "invite-only" }, expect: true }
        ]
      },

      # A sign-up that submitted nothing anybody could prove. Only possible when
      # every channel principal is optional, and it becomes an account at once.
      # A sign-up that gave no channel becomes an account immediately — but only
      # where something else can identify it afterwards. Without that, the account
      # could never sign in, and Principals refuses the row instead
      # (login_key_may_be_missing? below).
      "channel_less_registration?" => {
        source: "!contactable? && pending_registration? && " \
                "principals.select(&:channel?).all?(&:optional?) && !login_key_may_be_missing?",
        rows: [
          { flags: DOOR.merge(registration: "open"), expect: false, note: "email is required" },
          { flags: DOOR.merge(registration: "open", email: "optional", contactable: false), expect: false,
            note: "an account with no email and nothing else could never sign in" },
          { flags: DOOR.merge(email: "optional", username: true, contactable: false),
            expect: true, enabling: true, note: "the username identifies it" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "optional",
                              username: true, contactable: false),
            expect: true, note: "both channels skippable, username still guarantees a way in" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "required"),
            expect: false, note: "the phone must still be proved" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "optional", username: true),
            expect: false,
            note: "--contactable (the default) refuses the channel-less row, so the branch is dead" }
        ]
      },

      # Whether the "hold at least one channel" promise needs a record-level rule.
      # Only where it can actually fire — see the four ways it can't in the
      # generator. In practice: a username beside two optional channels.
      "contactable_validation?" => {
        source: "contactable? && >1 channel && none required && !login_principals.all?(&:channel?)",
        rows: [
          { flags: DOOR.merge(registration: "open"), expect: false,
            note: "one channel, and it's required — its own presence rule is the guarantee" },
          { flags: DOOR.merge(email: "optional", phone: "optional", username: true),
            expect: true, enabling: true,
            note: "the username satisfies at_least_one_login_key while holding no channel; " \
                  "no --registration=open needed — the rule is on the model, not the sign-up form" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "optional"),
            expect: false,
            note: "every login key IS a channel, so at_least_one_login_key already emits this exact rule" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "required", username: true),
            expect: false, note: "a required channel is the guarantee" },
          { flags: DOOR.merge(registration: "open", email: "optional", phone: "optional",
                              username: true, contactable: false),
            expect: false, note: "--no-contactable: no promise to keep" }
        ]
      },

      # Whether a staged sign-up carries anything across to the account besides the
      # channel a proof just settled. Where false, PendingRegistration emits neither
      # the staged_attributes method nor the splat that reads it — an account minted
      # from a proof and nothing else.
      "staged_attributes?" => {
        source: "staged_attributes_entries.any? — non-channel principals, plus the password",
        rows: [
          { flags: DOOR, expect: true, enabling: true, note: "the password digest carries" },
          { flags: { magic_link: true }, expect: false,
            note: "email is a channel and there is no password: nothing to carry" },
          { flags: { magic_link: true, username: true }, expect: true,
            note: "the username needs no proof, so it carries" },
          { flags: DOOR.merge(phone: "required"), expect: true, note: "still the password" },
          { flags: { passkey: true, email: "optional", username: true }, expect: true,
            note: "no password, but the username carries" }
        ]
      },

      # Whether PendingRegistration opens a private section at all. Everything under
      # it is conditional, so in a build that carries nothing, defers nothing and
      # claims no username, the keyword would be the last line before `end`.
      "pending_registration_privates?" => {
        source: "staged_attributes? || deferred_phone? || omniauth? || " \
                "!principals.username.nil?",
        rows: [
          { flags: DOOR, expect: true, enabling: true, note: "staged_attributes carries the digest" },
          { flags: { magic_link: true }, expect: false,
            note: "nothing carries, nothing defers, nothing supersedes, no username — every method is public" },
          { flags: { magic_link: true, username: true }, expect: true, note: "username_not_taken" },
          { flags: { magic_link: true, email: "required", registration: "open", phone: "required" }, expect: false,
            note: "registration proves both channels before account creation" }
        ]
      },

      # Whether a record could be saved with every login key blank — an account that
      # signs in once and is then unreachable forever. Where true, Principals gets a
      # record-level check; where false, some column's own presence rule already
      # guarantees it and a second one would be dead code.
      "login_key_may_be_missing?" => {
        source: "login_principals.all?(&:optional?)",
        rows: [
          { flags: DOOR, expect: false, note: "email is required" },
          { flags: DOOR.merge(email: "optional", contactable: false), expect: true, enabling: true,
            note: "the only login key can be blank" },
          { flags: DOOR.merge(email: "optional", phone: "optional"), expect: true,
            note: "two keys, both skippable — a sign-up can supply neither" },
          { flags: DOOR.merge(email: "optional", username: true), expect: false,
            note: "username is always required, so there is always a way in" },
          { flags: DOOR.merge(email: "optional", phone: "required"), expect: false,
            note: "the number is guaranteed" },
          { flags: DOOR.merge(phone: "required"), expect: false }
        ]
      },

      "authorization?" => {
        source: "adminable? || teams?",
        rows: [
          { flags: DOOR, expect: false },
          { flags: DOOR.merge(adminable: true), expect: true, enabling: true },
          { flags: DOOR.merge(teams: "scope"), expect: true },
          { flags: DOOR.merge(teams: "session"), expect: true,
            note: "every mode resolves the active team through the member's own teams" }
        ]
      }
    }.freeze

    # ---------------------------------------------------------------------
    # The table above is the specification; everything below just runs it.
    # ---------------------------------------------------------------------

    def self.build(flags) = AuthnzElevenGenerator.new([], flags)

    # Predicates are private because Thor turns public methods into generator
    # commands (a public `email_verifiable?` would try to run as a build step).
    def self.evaluate(flags, predicate) = build(flags).send(predicate)

    # Would the generator accept this flag set at all? Computed, not declared.
    def self.legal?(flags)
      generator = build(flags)
      FLAG_VALIDATORS.each { |validator| generator.public_send(validator) }
      true
    rescue Rails::Generators::Error
      false
    end

    TRUTH_TABLES.each do |predicate, spec|
      spec[:rows].each_with_index do |row, index|
        define_method(:"test_#{predicate.delete_suffix("?")}_row_#{index}") do
          actual = self.class.evaluate(row[:flags], predicate)
          assert_equal row[:expect], actual,
                       "#{predicate} (#{spec[:source]}) with #{row[:flags].inspect} " \
                       "should be #{row[:expect]}#{" — #{row[:note]}" if row[:note]}"
        end
      end
    end

    # An enabling row the validators reject isn't a build the generator accepts,
    # so it can't be the canonical way to enable the predicate.
    def test_every_enabling_row_is_a_flag_set_the_generator_accepts
      TRUTH_TABLES.each do |predicate, spec|
        spec[:rows].select { |row| row[:enabling] }.each do |row|
          assert self.class.legal?(row[:flags]),
                 "#{predicate}'s enabling row #{row[:flags].inspect} is rejected by the validators"
        end
      end
    end

    # Exactly one canonical enabling build per predicate.
    def test_every_predicate_has_exactly_one_enabling_row
      TRUTH_TABLES.each do |predicate, spec|
        enabling = spec[:rows].select { |row| row[:enabling] }
        assert_equal 1, enabling.size,
                     "#{predicate} must have exactly one `enabling:` row (the minimal legal " \
                     "build that turns it on); found #{enabling.size}"
      end
    end

    # Enabling rows deliberately larger than strictly necessary, each with a
    # reason. An exception carries a one-line justification or it isn't an exception.
    NON_MINIMAL_ENABLING_ROWS = {
      "fail_open_sudo?" =>
        "sudoable? && (omniauth? || !password?): dropping --password " \
        "leaves a legal set that is still true, but true via the !password? branch " \
        "rather than the omniauth? one. The password flag is what pins the omniauth route."
    }.freeze

    # The `enabling:` label claims "canonical": drop any single flag and the
    # predicate goes false, or the build stops being legal. Without this, a row
    # could quietly accumulate flags nobody needs and still look correct.
    def enabling_flags_for(predicate)
      TRUTH_TABLES.fetch(predicate)[:rows].find { |row| row[:enabling] }[:flags]
    end

    # Flags that could be dropped from +flags+ with +predicate+ staying both
    # true and legal — i.e. flags the row doesn't need.
    def self.redundant_flags(predicate, flags)
      flags.keys.select do |flag|
        smaller = flags.reject { |key, _| key == flag }
        evaluate(smaller, predicate) && legal?(smaller)
      end
    end

    def test_enabling_rows_are_minimal
      minimal_predicates = TRUTH_TABLES.keys - NON_MINIMAL_ENABLING_ROWS.keys

      minimal_predicates.each do |predicate|
        flags = enabling_flags_for(predicate)
        redundant = self.class.redundant_flags(predicate, flags)

        assert_empty redundant,
                     "#{predicate}'s enabling row #{flags.inspect} is not minimal: " \
                     "#{redundant.map { |f| "--#{f}" }.join(", ")} can be dropped and it stays " \
                     "true and legal. Shrink it, or allowlist it with a reason."
      end
    end

    # The mirror of the above: an allowlisted exception that has become minimal
    # is a stale entry, and staleness is exactly what an allowlist rots into.
    def test_allowlisted_non_minimal_rows_are_still_non_minimal
      NON_MINIMAL_ENABLING_ROWS.each_key do |predicate|
        redundant = self.class.redundant_flags(predicate, enabling_flags_for(predicate))

        refute_empty redundant,
                     "#{predicate} is allowlisted as non-minimal, but its enabling row is " \
                     "minimal now — drop the NON_MINIMAL_ENABLING_ROWS entry"
      end
    end

    # An enabling row that doesn't actually turn the predicate on is a broken claim.
    def test_every_enabling_row_actually_turns_its_predicate_on
      TRUTH_TABLES.each do |predicate, spec|
        row = spec[:rows].find { |r| r[:enabling] }
        assert_equal true, self.class.evaluate(row[:flags], predicate),
                     "#{predicate}'s enabling row #{row[:flags].inspect} does not make it true"
      end
    end

    # Guards the "illegal set" rows above: they're only interesting as
    # documentation if they really are illegal. If a validator loosens, this
    # tells us the row is now stale rather than silently lying.
    def test_rows_documented_as_illegal_are_actually_rejected
      illegal_rows = TRUTH_TABLES.flat_map do |predicate, spec|
        spec[:rows].select { |row| row[:note]&.include?("ILLEGAL") }.map { |row| [predicate, row] }
      end
      refute_empty illegal_rows, "expected some rows to document illegal flag sets"

      illegal_rows.each do |predicate, row|
        refute self.class.legal?(row[:flags]),
               "#{predicate}'s row #{row[:flags].inspect} is documented as an illegal flag " \
               "set, but the validators accept it — the note is stale"
      end
    end

    # Completeness: every predicate a template branches on has a truth table.
    # Derived from the templates rather than a hand-kept list, so a new
    # `<% if new_predicate? %>` fails here until it gets a table.
    TEMPLATES_ROOT = File.expand_path("../../lib/generators/authnz_eleven/templates", __dir__)

    # Code inside ERB tags, across every template.
    def self.template_code
      Dir.glob("#{TEMPLATES_ROOT}/**/*").select { |path| File.file?(path) }.flat_map do |path|
        File.read(path, encoding: "UTF-8", invalid: :replace).scan(/<%-?(.*?)-?%>/m).flatten
      end
    end

    # Predicates the templates branch on: bare `foo?` calls with no explicit
    # receiver, which are therefore calls on the generator itself.
    # `identity.namespaced?` / `principals.email.optional?` are value-object
    # predicates, covered by their own unit tests rather than this table.
    def self.branched_predicates
      template_code
        .flat_map { |code| code.scan(/(?<![.\w])([a-z_][a-z_0-9]*\?)/).flatten }
        .uniq
        .select { |name| AuthnzElevenGenerator.private_method_defined?(name) }
    end

    def test_every_predicate_the_templates_branch_on_has_a_truth_table
      branched = self.class.branched_predicates

      # Guards the guard: a regex that quietly matched nothing would make this
      # test pass forever while asserting nothing at all.
      refute_empty branched, "found no predicates in the templates — the scan is broken"

      missing = branched - TRUTH_TABLES.keys
      assert_empty missing,
                   "these predicates are branched on in templates but have no truth " \
                   "table: #{missing.sort.join(", ")}"
    end

    # An emitted test helper that posts to the sudo route in a build with no sudo
    # route is a NameError nothing but the boot tier ever sees, and it takes the
    # whole passkey ceremony suite down with it.
    def test_the_emitted_sudo_clearing_helper_names_no_route_a_build_lacks
      refute_includes self.class.build(password: true, passkey: true).send(:test_clear_sudo_body), "sudo_path"
      assert_includes self.class.build(password: true, passkey: true, sudoable: true).send(:test_clear_sudo_body),
                      "user_sudo_path"
    end
  end
end
