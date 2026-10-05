# frozen_string_literal: true

module AuthnzEleven
  # The single source of truth for generator scenarios.
  # Each entry is `name => [invocation, …]`, where an invocation is a flag array;
  # more than one = a multi-identity / --namespaced build rendered into the same app
  # in order.
  #
  # Two readers, one list:
  #   - ScenarioCompletenessTest (fast, in-process): asserts these collectively
  #     build every template.
  #   - BootScenariosTest (slow): builds, boots, and runs each generated app's own
  #     test suite.
  #
  # Keep it flat and named — realistic configs, not a combinatorial machine.
  module Scenarios
    ALL = {
      "default" => [%w[--password --registration=open --email]],
      "api_tokens" => [%w[--password --username --no-contactable --api-tokens]],

      # Everything at once, single identity — the broadest single build.
      "kitchen_sink" => [%w[--password --registration=open-and-invites --recoverable
                            --second-factor=totp,webauthn --trackable --admin-dashboard
                            --sudoable --deadboltable --bannable --teams=session --pwned
                            --strong-passwords --captchable --guestable --easy-dev-login
                            --impersonatable --last-seenable --rememberable --timeoutable
                            --omniauth --security-notifications --api-tokens --email]],

      # The other kitchen sink: phone first, email optional, every second factor,
      # encrypted PII, coy, and --deadboltable beside --password-historical (a reset
      # saves twice, and the history check once failed the second save).
      "kitchen_sink_phone" => [%w[--password --phone=required --email=optional --username
                                  --registration=open-and-invites --recoverable --second-factor=totp,webauthn,sms
                                  --deadboltable --bannable --rememberable --max-sessionable --timeoutable
                                  --last-seenable --trackable --captchable --coy --encrypted-pii --sudoable
                                  --admin-dashboard --impersonatable --api-tokens --security-notifications
                                  --password-rotatable --password-historical --guestable --teams]],

      # No password anywhere, both channels optional, every door but the password and
      # every second factor. The fixture's email is a way in through the magic link
      # even though the build guarantees none, and a magic-link sign-in is never
      # stepped up — both broke tests that reasoned from the build alone.
      "passwordless_everything" => [%w[--email=optional --phone=optional --username
                                       --registration=open-and-invites --guestable --magic-link --passkey
                                       --omniauth --timeoutable --max-sessionable=prompt --last-seenable
                                       --trackable --api-tokens --second-factor=sms,webauthn,totp --sudoable
                                       --captchable --admin-dashboard --bannable --impersonatable
                                       --easy-dev-login]],

      # Typed sign-up through the two texted/emailed doors with no password, and a
      # security key as the only second factor behind sudo. The sudo bar is then a
      # key the account only holds after enrolling its first one.
      "passwordless_typed" => [%w[--magic-link --sms-code --email=optional --phone=optional --registration=open
                                  --second-factor=webauthn --sudoable --security-notifications]],

      # Security keys as the ONLY second factor — impossible before --second-factor
      # split, because --webauthn dragged TOTP in with it. The build that proves the
      # split: no totp_secret column, no authenticator controller, and
      # second_factor_enrolled? answering from the keys themselves. --admin-dashboard
      # is here on purpose — with no QR to embed in the dashboard, the admin-MFA hold
      # lands on the settings security-keys page instead, and only this shape
      # exercises that. Password expiry adds a later hold so enrollment must hand
      # over recovery codes before a new request can be diverted to the password page.
      "security_keys_only" => [%w[--password --registration=open --second-factor=webauthn
                                  --admin-dashboard --sudoable --password-rotatable --email]],

      # "reddit": --username as a second login key, email demoted to optional.
      # --username alone is a login key, not a strategy, so it still needs a door.
      # Classic reddit: a username and a password, and an email you may simply not
      # give. --no-contactable is what says so — with --contactable (the default) a
      # lone optional channel is refused, because "optional" would have nothing to be
      # optional against. This is the only scenario that exercises the contactless
      # branch (channel_less_registration?).
      "reddit" => [%w[--password --username --email=optional --registration=open --no-contactable]],

      # The same contactless shape with a provider beside it, which is the only way
      # to reach claim_without_verification from the OmniAuth callback: some
      # providers return no address, and then there is nothing to prove and nothing
      # to wait for. Was uncovered — no scenario combined --no-contactable with
      # --omniauth, so the account-plus-provider-login write on that path was never
      # driven by a test.
      "omniauth_no_channel" => [%w[--omniauth --username --email=optional --registration=open --no-contactable]],

      # Modern reddit: give a number OR an address, and it doesn't matter which.
      # The only shape where must_be_contactable is generated — two optional
      # channels beside a login key that isn't one — and the only password build
      # where the blank-phone branch in RegistrationsController is reachable.
      "reddit_modern" => [%w[--password --username --email=optional --phone=optional
                             --registration=open --omniauth]],

      # Phone as a login principal + channel, with SMS verification (3b). The
      # richest sign-in dispatch — three keys (username/email/phone) — plus the
      # phone column + partial unique index, settings/phones, the SMS seam,
      # cache-backed challenges, the code-entry flow, and guests carrying a nil phone
      # (--guestable relaxes NOT NULL).
      "phone" => [%w[--password --registration=open --username --phone=required --guestable --email]],

      # A required phone with no sign-up form behind it, so nothing mints an account
      # before the number is proved and the requirement stays an ordinary presence
      # validation. The only shape that emits `unless: :guest?` and the
      # PendingRegistration#guest? stub that answers it (guest_excused_from_phone?);
      # every other guests-plus-phone build hands enforcement to the completion gate.
      "guest_phone" => [%w[--password --registration=closed --guestable --phone=required --email]],

      # Both channels, email optional — the only build where which channel gates
      # sign-up is decided per request: give an email and the verification mail
      # gates it (a taken phone is then answered honestly, since no mail would
      # arrive to cover it); skip the email and the SMS code gates it instead.
      "phone_optional_email" => [%w[--password --registration=open --phone=required --email=optional]],

      # Phone-gated sign-up whose new account still needs to choose a durable door.
      # Completing the SMS proof signs in, then the shared completion funnel sends
      # the account to /finish_setup rather than directly to root.
      "phone_credential_enrollment" => [%w[--password=deferred --passkey --registration=open
                                           --phone=required --email=optional]],

      # Principal changes behind a sudo bar. No scenario carried --sudoable
      # ALONGSIDE a phone principal, so when the sudo rework guarded
      # Settings::PhonesController#update, the phone-verification tests kept
      # posting the password_challenge that action no longer takes — five tests
      # failing in a build nothing built.
      #
      # Carries --passkey --omniauth so the sudo bar is NOT the single-bar shortcut
      # (unconditional_password_bar? is false once a provider account can exist),
      # which is what makes sudo_test_mode a real dispatch here rather than a
      # constant.
      #
      # --username, deliberately: the same build without it also trips the open
      # question of whether an account may be minted holding no login key at all,
      # which is a design decision, not a regression. The login key keeps this
      # scenario about sudo.
      "sudoed_principals" => [%w[--password --registration=open-and-invites --username
                                 --email=optional --phone=optional --passkey --omniauth --sudoable]],

      # A phone column with no SMS vendor: --no-verifiable is the way to opt out
      # of the channel machinery. Reaches the phone-without-SMS-challenge branches
      # — and it drops email verification too, which is the coupling a per-channel
      # opt-out would one day relieve.
      "phone_no_sms" => [%w[--password --registration=open --phone=required --no-verifiable --email]],

      # A permanent email: the address an account is created with is the one it
      # keeps, so /settings has no email form and the whole staged-change apparatus
      # behind it (pending_email, its token and mailer, the confirm and resend
      # endpoints) is gone. Registration verification stays — permanent drops only
      # the CHANGE half, and this is the scenario that tells the two apart.
      # --phone=optional is here so the build carries one permanent principal beside
      # one changeable one, which is the shape that proves the modifier is per
      # principal rather than per build. It also gives the sudo suite a form to
      # reach for: its "answered inline" test uses the email form everywhere else,
      # and the only sudo-guarded action left in a permanent build without it is
      # deleting the account, which destroys the session it wants to read back.
      "permanent_email" => [%w[--password --registration=open --email=required,permanent
                               --phone=optional --sudoable]],

      # A permanent phone, which needs the number collected at sign-up rather than
      # after it — so, which is what keeps the account from being
      # minted before its number exists (the shape validate_permanent! refuses).
      # The anti-sybil anchor: a verified number reserves itself for good.
      "permanent_phone" => [%w[--password --registration=open --username
                               --phone=required,permanent]],

      # Phone as the sole login key and channel (, no --username): a
      # single-key phone sign-in, no email column, no verification.
      "phone_only" => [%w[--password --registration=open --phone=required]],

      # The SMS door as the ONLY way in: no password, no email column, so the phone
      # is the sole principal and a texted code the sole credential. Reaches the
      # two-step door, the collapse of the sign-up gate into it (registration hands
      # its token to the door's code step), and the sign-in page with no password
      # form on it at all.
      "sms_code_only" => [%w[--registration=open --sms-code --phone]],

      # The same door with an admin area, whose admins land on /admin after signing in.
      "sms_code_admin" => [%w[--sms-code --phone --easy-dev-login --admin-dashboard --impersonatable --bannable
                              --registration=open]],

      # The door beside a password, with verification switched off — the combination
      # that proves the SMS plumbing no longer rides phone_verifiable?.
      "sms_code_no_verify" => [%w[--password --registration=open --sms-code --phone --no-verifiable --email]],

      # A texted code as the ONLY second factor, the phone sibling of
      # security_keys_only. --sms-code is absent and refused here: the door and the
      # factor are the same proof of the same phone. --admin-dashboard puts the
      # admin-MFA hold on the settings SMS page (no QR to land on), and --sudoable
      # guards turning the factor off.
      "sms_second_factor" => [%w[--password --registration=open --phone=required
                                 --second-factor=sms --admin-dashboard --sudoable --email]],

      # Invite-only with both channels required: the invitation proves its own, and the
      # typed other one is gated exactly as in an open sign-up. invite_only_staged
      # covers the optional channel an invitation drops instead.
      "invite_both_channels" => [%w[--password --registration=invite-only --phone=required --email=required]],

      # A signed invitation link delivered only by SMS. This is also the shape
      # that proves invitations can pull in delivery without a code challenge.
      "invite_only_sms" => [%w[--password --registration=invite-only --phone=required]],

      # Open registration with either invitation channel available at runtime.
      "sms_invitations" => [%w[--password --registration=open-and-invites
                               --phone=required --email=optional]],

      # Invite-only with a provider as the only door and a required email: an
      # address-less provider is told so, not told registration is invite-only.
      "omniauth_invite_teams" => [%w[--omniauth --username --registration=invite-only --email
                                     --teams=middleware --admin-dashboard --impersonatable]],

      # Invite-only beside --omniauth, so the provider sign-up and the typed one both stage.
      "invite_only_staged" => [%w[--password --registration=invite-only --omniauth --phone=required --email=optional]],

      # Door-only builds — each reaches templates the --password configs never
      # touch (magic-link, passkey sessions, the omniauth completion interstitial,
      # the passwordless easy-dev-login controller).
      "magic_only" => [%w[--magic-link --registration=closed --email]],
      "passkey_only" => [%w[--passkey --registration=closed --email]],
      # Social login as the ONLY door, with no typed sign-up form. The callback is
      # the whole registration path, so this is where staging has to hold a
      # provider's unproved address, and where the
      # enrollment gate sends people to link a provider rather than enroll a passkey.
      "omniauth_complete" => [%w[--omniauth --username --email]],

      # The same plus a typed sign-up form, which mints an account holding nothing
      # until the enrollment gate catches it.
      "omniauth_typed_signup" => [%w[--omniauth --username --registration=open --email]],

      # A typed sign-up that leaves the phone blank has no door but a provider, so
      # finish-setup offers only the provider button. The only build that reaches it.
      "provider_enrollment" => [%w[--omniauth --sms-code --phone=optional --registration=open --email]],

      # Two removable doors and no guaranteed one. This is the build where the old
      # generation-time last-credential guards both declined to fire, so a
      # provider-registered account could unlink its way into a lockout.
      "passkey_omniauth" => [%w[--passkey --omniauth --registration=open --sudoable --email]],

      # Both WebAuthn roles in one build, which is the only shape where the shared
      # credentials table has to tell them apart (the passkey flag and its scopes).
      # --password is here so the second factor engages at all: a passkey door never
      # steps up, so without another door the challenge would be unreachable.
      "passkey_and_security_key" => [%w[--password --passkey --second-factor=webauthn
                                        --registration=open --sudoable --email]],
      "easy_dev_passwordless" => [%w[--magic-link --easy-dev-login --email]],

      # The only scenario where the sign-up form calls the password optional: the
      # field may be left blank, and an account may give its password up afterwards.
      # Reaches every password_form_optional? branch — the blank-allowed form, the
      # settings remove action, and the sudo bar that asks the digest rather than
      # assuming one.
      #
      # Deliberately no --magic-link. The removal-refusal test needs a fixture whose
      # only door IS the password, and a magic-link build gives every fixture a
      # second one off its address.
      "password_optional" => [%w[--password=optional --omniauth --registration=open --sudoable --email]],

      # The modern-Reddit shape: the sign-up form has no password field at all, and
      # whether you are asked for one afterwards depends on what your entry path
      # left you holding. Typed email arrives with sign_in_methods == [] and is held
      # at the password page; a provider sign-up arrives holding :omniauth and walks
      # straight through. One predicate, two behaviours — which is the whole point
      # of --password=deferred.
      #
      # No --passkey, so credential_enrollment_path resolves to the password page
      # rather than the passkey one.
      "password_deferred" => [%w[--password=deferred --omniauth --registration=open --recoverable --email]],

      # Deferred where every account already holds a door from birth: a verified
      # address IS a magic link, so sign_in_methods is never empty and no
      # enrollment hold is generated at all.
      "password_deferred_covered" => [%w[--password=deferred --magic-link --passkey --registration=open --email]],

      # The only shape with a real choice at the enrollment hold: nothing was
      # established by signing up, and both a passkey and a password are worth
      # offering. --omniauth is here to pin that it is NOT offered — reaching the
      # hold means the typed route was taken, which means the provider button was
      # already declined.
      # --sudoable is here so this is the one build holding all three of a nullable
      # password, a WebAuthn credential, and a sudo bar — the shape where a lost
      # authenticator used to block setting a password (the only way back).
      "credential_chooser" => [%w[--password=deferred --passkey --omniauth --registration=open --sudoable --email]],

      # The Basecamp-style middleware that reaches the team_slug initializer.
      "middleware_teams" => [%w[--password --teams=middleware --email]],

      # /:team_id route-scoped teams, invite-only. Accepting an invitation as an
      # existing account lands on the team's URL, and the invitation proves the one
      # channel, so the row completes without reaching a verification gate.
      "invited_url_teams" => [%w[--password --teams --registration=invite-only --email]],

      # Admin area with impersonation but no MFA gate, so the impersonation
      # behavioral test runs unblocked (kitchen_sink's --two-factor forces admin
      # MFA setup before an admin may impersonate). --trackable so the same test
      # can assert the impersonation event bracket. Also runs the session-lifecycle
      # test's --last-seenable / --rememberable / --timeoutable / --max-sessionable
      # (bare = evict) paths outside the kitchen-sink noise. --password-rotatable
      # adds an impediment, which is what makes the admin area's "a non-admin
      # held in purgatory still gets a 404, not a redirect to their gate" test
      # emit — the ordering that not_found_unless exists to guarantee.
      "admin_impersonation" => [%w[--password --admin-dashboard --impersonatable --trackable
                                   --last-seenable --rememberable --timeoutable --max-sessionable
                                   --password-rotatable --email]],

      # Password expiry: an impediment that keeps a signed-in user with
      # an aged-out password at the change-password page. Combined with --omniauth
      # to exercise password_fresh?'s provider exemption (a provider user's random
      # placeholder password must never trip the gate).
      "password_rotation" => [%w[--password --registration=open --password-rotatable --omniauth --email]],

      # Password-reuse history: archives each replaced digest and rejects reuse of a
      # recent one. A model validation (no hold), so a model test carries it.
      "password_history" => [%w[--password --registration=open --password-historical --email]],

      # TWO holds in one build. If each hold's page skipped only its own gate, a
      # user both over the cap and expired would bounce between /settings/sessions
      # and /settings/password/edit forever. Single-hold tests cannot catch that cycle.
      # Also the only --max-sessionable=prompt build with a password, where an
      # over-cap sign-in is held at the session page instead of silently evicting.
      "queued_holds" => [%w[--password --registration=open --max-sessionable=prompt
                            --password-rotatable --email]],

      # --coy: the evasive branch of every enumeration-aware flow — password
      # reset, magic-link request, sign-up on a taken email, the locked-account
      # message, email change, phone change, SMS sign-in, invitations — instead of
      # the honest default. Carries a phone principal on purpose: --coy has to reach
      # BOTH channels, and a phone-free scenario is exactly why the settings phone
      # change once ignored the flag entirely.
      "coy_existence" => [%w[--password --registration=open-and-invites --recoverable
                             --magic-link --sms-code --deadboltable --phone=required --coy --email]],

      # A default identity plus a heavily-flagged --namespaced second one, and two
      # more namespaced shapes: --username as a second login key, and two independently
      # --registration=open-and-invites identities (each needs its own accept_invitation route helper —
      # asserted in BootScenariosTest::EXTRA_CHECKS).
      # The namespaced identity is passwordless, so it carries --bannable and not
      # --deadboltable: there are no password guesses to count against a passkey, and
      # shutting such an account off is a ban's job (validate_deadboltable! refuses
      # the pairing outright).
      "namespaced_admin" => [%w[--password --registration=open --email],
                             %w[--passkey --sudoable --trackable --timeoutable --bannable --api-tokens
                                --registration=invite-only --namespaced --user-class=Admin --email]],
      "namespaced_username" => [%w[--password --registration=open --email],
                                %w[--password --username --recoverable --security-notifications --api-tokens
                                   --namespaced --user-class=Realtor --email]],

      # Two identities that both text: the second gets its own Realtor::SmsChallengeable
      # model/table while reusing the first writer's identity-free app/lib/sms.rb
      # and delivery job. The shape most likely to collide, so it earns a scenario.
      # --sms-code on the namespaced side: its sign-in lands on the identity's own root.
      "namespaced_phone" => [%w[--password --registration=open --phone=required --email],
                             %w[--password --phone=required --sms-code --namespaced --user-class=Realtor --email]],
      # A namespaced identity with no door a test can drive (passkey + provider), a
      # phone, two second factors and sudo. Its tests sign in with a stand-in passkey
      # and answer every sudo bar with it.
      "namespaced_passwordless" => [%w[--magic-link --email],
                                    %w[--passkey --omniauth --username --email=optional --phone=optional
                                       --namespaced --user-class=Vendor --registration=open
                                       --second-factor=webauthn,totp --sudoable --api-tokens]],
      "two_invitable" => [%w[--password --registration=open-and-invites --email],
                          %w[--password --registration=open-and-invites --namespaced --user-class=Realtor --email]],

      # The only scenario pairing --namespaced with --omniauth, which is why the namespaced
      # callback route sat outside OmniAuth's path_prefix unnoticed. Deliberately not
      # --registration=invite-only: the completion tests don't seed an invitation, a separate gap.
      "namespaced_omniauth" => [%w[--omniauth --username --email],
                                %w[--omniauth --username --namespaced --user-class=Realtor --email]],

      # A namespaced identity owning its own teams, admin area and invitations while the
      # default identity has none of them — the order that used to leave it without
      # Current.team. And two identities with the same broad flags, which used to
      # collide on every shared file.
      "portal_isolation" => [%w[--password --teams --admin-dashboard --impersonatable --email],
                             %w[--password --namespaced --user-class=Merchant --email]],
      "namespaced_teams" => [%w[--password --email],
                             %w[--password --teams --admin-dashboard --registration=open-and-invites
                                --namespaced --user-class=Merchant --email]],
      "twin_identities" => [%w[--password --registration=open-and-invites --second-factor --admin-dashboard
                               --impersonatable --sudoable --trackable --teams=session --captchable --email],
                            %w[--password --registration=open-and-invites --second-factor --admin-dashboard
                               --impersonatable --sudoable --trackable --teams=session --captchable
                               --namespaced --user-class=Merchant --email]]
    }.freeze
  end
end
