# Authnz Eleven

Authnz Eleven is an authentication **generator** for Rails. It ***is*** intended to be an [all-singing, all-dancing answer to most authentication concerns](https://github.com/rails/rails/pull/52328). Use it to build your own bespoke auth system or model one after an auth system used on a site you know. Most common authentication flows and features can be expressed with it. 

You can think of this gem as a little bit
like a compiler. It will always try to emit the simplest code possible with the fewest
parts possible. Anything you don't use, you don't pay any complexity or overhead tax for.
Because it is generated into your project, customization is
infinite. If you want three-factor authentication, add it.

The generated architecture is opinionated and has been designed to be easy for humans to understand, easy to extend,
and hard to get wrong. It aims for strong account protection without making
ordinary account management needlessly hostile. In addition to standard account
protection, builds also resist account-squatting, pre-account hijacking, and other kinds of attacks.
The defaults deliberately balance security, recovery, and convenience.

Quick highlights:

- **Sign in with email, phone, or username.** Phone and email can be verified or optional.

- **Use passwords, passkeys, magic links, social login, SMS sign-in**, or any combination thereof.

- **Optionally, stay coy about the existence of user accounts**. Make flows respond the same whether or not the account exists and resist timing attacks.

- **Complete settings views**. You can leave it as-is or customize.

## Why

You may have heard that you shouldn't roll your own crypto, but you can roll your own auth. This is true, and truer now than ever before. You don't need a library or team of PhDs to design an auth system. But are you prepared to let your agent one-shot it? 

The basic case is easy enough, but depending on what you ask for, it can become quite tricky, and may take several iterations to get right. There are often a large number of edge cases to consider, and the consequences of flubbing one can be very serious. There is no one "spec" to hand off, because every app's authentication requirements are different. Conversely, agents can also be overzealous, adding needless complexity to prevent "bugs" that would in fact be harmless or moot.

Now you could call this under-specification, but that's just the thing: it's a case where the main bottleneck is *decisions* that must made about app behavior. So I went ahead and made them all for you. You can take this as a carefully considered, opinionated, and human-oriented starting point, so you can focus on only what actually needs changing.

## Requirements

Ruby >= 3.4.2

Rails >= 8.0.0

SQLite, PostgreSQL, or MySQL >= 8.0.13

## Install

```ruby
# Add this to your Gemfile
gem "authnz_eleven", group: :development
```

```bash
# then
bundle install
bin/rails generate authnz_eleven --email --password
bin/rails db:migrate # and whatever other instructions that are described in the post-install message
```

You must select at least one **identifier** (`--email`, `--phone`, or `--username`)
and one **sign-in method** (`--password`, `--magic-link`, `--sms-code`, `--omniauth`, or
`--passkey`).

## Wizard

There are quite a few flags, and some combinations don't work together, so if you'd rather have your hand held there is a wizard:

```ruby
# Add this to your Gemfile
gem "huh", github: "marcoroth/huh-ruby", group: :development
```

```bash
# then
bundle install
bin/rails generate authnz_eleven:wizard
```

## Sample builds

Each build lists only the flags that give it its shape. Add more to taste: `--trackable --rememberable --pwned --deadboltable --captchable`, and so on. Please note these are rough approximations.

### Hacker News / Reddit (old)

```bash
bin/rails generate authnz_eleven --username --password --email=optional --no-contactable --recoverable --no-verifiable
```

### Reddit (modern)

```bash
bin/rails generate authnz_eleven --username --password --email=optional --phone=optional --recoverable --omniauth
```

### WhatsApp / Signal

```bash
bin/rails generate authnz_eleven --phone --sms-code --registration=open-and-invites
```

### Slack

```bash
bin/rails generate authnz_eleven --email --magic-link --omniauth --teams --registration=open-and-invites
```

### GitHub

```bash
bin/rails generate authnz_eleven --username --email --password --recoverable --passkey --second-factor=totp,webauthn --sudoable
```

### Online store with guest checkout

```bash
bin/rails generate authnz_eleven --email --password --recoverable --guestable --rememberable
```

### Internal tool

```bash
bin/rails generate authnz_eleven --email --omniauth --registration=invite-only --admin-dashboard --impersonatable
```

### Shopify

```bash
bin/rails generate authnz_eleven --email --magic-link --guestable
bin/rails generate authnz_eleven --user-class=Merchant --namespaced --email --password --second-factor --teams
```

## Choices

All sessions are backed by a `Session` model. `ActiveSupport::CurrentAttributes` is used to reference the current user/session. Views are ERB.

## Generated code

Every build generates the identity model (`User` by default) and its `Authenticatable` concern,
`Session`, `Current`, the `Authentication` controller concern, sign in/sign
out controllers, a `/settings` area with a dashboard, signed-in device list, and delete account. Also a
starter test suite. A navigation partial is included and will be injected into the layout if it has not been modified yet.

## Registration and identifiers

At least one identifier is needed to create an account, either an email, phone, or username. Having only a single optional email or phone will not work. However, having *both* an optional email *and* optional phone *will* (`--email=optional --phone=optional`), the user will just need to pick which one they want to supply, and this rule will prevent them from changing their email/phone later to remove both.

| Flag | Adds |
| --- | --- |
| `--registration[=open\|open-and-invites\|invite-only\|closed]` | Account creation policy: `open` (default) means registration is public. `open-and-invites` allows users to invite others via email or phone, or invite them to teams if using `--teams` too. `invite-only` prevents public registration without an invite. See [Invitations](#invitations). `closed` means accounts must be created some other way in the backend. |
| `--email[=required[,permanent]\|optional]` | Login with email address. If `required` (default), you may also set `permanent` to prevent users changing it. `optional` with `permanent` is not supported. Email addresses are validated with [valid_email2](https://github.com/micke/valid_email2) and by default also refuse disposable domains. |
| `--phone[=required[,permanent]\|optional]` | Login with phone number. If `required` (default), you may also set `permanent` to prevent users changing it. `optional` with `permanent` is not supported. Stored in E.164 and validated with [phonelib](https://github.com/daddyz/phonelib). By default all countries are allowed, but you can restrict this in the initializer. |
| `--username` | A required, unique, unchangeable username. Uniqueness is compared case-insensitively, but the original casing is stored for display. Comes with a customizable blacklist for names like `admin` or `404`, etc. |
| `--contactable` | **On by default.** Requires that every account hold at least one channel identifier (an email address or phone number) so that you may contact them. |
| `--verifiable` | **On by default.** Verify ownership of emails and phones by sending a verification email or texting a six-digit code. No-op if you only have usernames. |
| `--coy` | Never reveal whether an account exists for a given email or phone number in any of the flows. For example, when doing the reset password flow, respond the same way whether an account with that email exists or not. Usernames are considered public and flows concerning them will always respond candidly regardless. Being coy is generally worse for user experience, and although we'll attempt to stymie timing attacks by deferring most timeable work to an `AuthnzElevenDeferredJob`, dedicated analysis can still reveal whether an account exists due to lookup miss vs hit timings. Cannot be used with `--no-verifiable`. |
| `--encrypted-pii` | Encrypt the email and phone at rest with Active Record Encryption. Covers invitations and `pending_*` fields as well. Encryption is deterministic so `find_by`/`where`/`exists?` and unique indexes will still work, but `LIKE %search%` will not. |
| `--guestable` | Anonymous guest users. See [Guests](#guests). |

If `--verifiable` is on, sign-up will be staged in a `PendingRegistration` model until the email or phone is verified. If both are required, they both must be verified. Only upon satisfaction of verification and credential requirements will the account be created and added to the `users` table. Doing it like this prevents account-squatting, pre-account hijacking, and keeps the code from having to check if users are verified. One side effect though is that registrations that are abandoned will hang around. You can run the included rake task or schedule the cleanup job by uncommenting the entry in `config/recurring.yml`.

```bash
bin/rails authnz_eleven:delete_expired_pending_registrations
```

At this time there is no option to let users in a `--verifiable` build create an account with a grace period before requiring they verify their phone/email, but you can of course hack that in yourself.

## Sign-in methods

Only the sign-in methods for the flags included will exist in the generated build. If you do not specify `--password`, then passwords will not be an available method for signing in.

| Flag | Adds |
| --- | --- |
| `--password[=required\|optional\|deferred]` | Password sign-in (`has_secure_password`). `required` (default) puts a mandatory password field on the sign-up form. `optional` lets you leave it blank. `deferred` puts password input after email/phone verification.|
| `--magic-link` | Sign in by emailed link. Requires `--email`. |
| `--sms-code` | Sign in by texted six-digit code. Requires `--phone`. |
| `--passkey` | Passkeys as a passwordless first-factor using the `webauthn` gem. |
| `--omniauth` | Social / SSO login via `omniauth` gem. You will need to set up a provider in the included initializer. |

## Passwords

**Disclaimer**: I do not recommend using passwords if you can avoid it. They are phishable, easy to forget, often make up the majority of IT support calls, and engender a need for more mechanisms in order to keep accounts safe. The few advantages are that they are conceptually simple and familiar to users and easy to share. Many websites will require passwords and then bolt on passkeys as an alternative sign-in method. I say that this is requiring user accounts to have a phishing vector. Better to not include passwords at all. All that being said, if you must use passwords, I suggest including another sign-in method as well, and `--pwned` and `--deadboltable` at the very least. It is up to your wisdom which of the others to include, based on your cohort of users.

Any one of the following will imply the `--password` flag.

| Flag | Adds |
| --- | --- |
| `--recoverable` | Password reset by emailed link. |
| `--pwned` | `not_pwned` validation against Have I Been Pwned using `pwned` gem. |
| `--strong-passwords` | Reject weak passwords by their `zxcvbn` strength score, adjustable in initializer. |
| `--deadboltable` | Too many failed sign-ins deadbolts the password door shut for a duration. A deadbolted account may still use other sign in methods, like passkeys or magic links, because they are not guessable, and if an attacker has access to your email they can just reset your password anyway. Use `authenticate_with_password` instead of `authenticate`. |
| `--password-rotatable` | Require changing passwords every 90 days (by default). The user will be held at the change-password page until they set a new one. **Note**: NIST SP 800-63B advises *against* forced rotation because it encourages formulaic passwords.  |
| `--password-historical` | Reject a password matching any of the last 5 (default).

## Sessions

Control how long sessions may exist and under what conditions they be created.

| Flag | Adds |
| --- | --- |
| `--rememberable` | A "remember me" checkbox on password sign-in. Checked, the cookie gets a lifetime that survives the browser closing. Unchecked, it's a browser-session cookie. |
| `--timeoutable` | Expire sessions after a period of inactivity. |
| `--max-sessionable[=evict\|prompt]` | Cap concurrent sessions. `evict` (default) signs out the least-recently-active session. `prompt` holds the new sign-in at the session list until the user signs one out. |

## API tokens

`--api-tokens` adds personal access tokens and a management page at `/settings/api_tokens`. Users can create and revoke tokens. Secrets are shown once and stored only as digests. Tokens expire after 90 days.

### Using tokens in your API

The generator includes an `ApiTokenAuthentication` concern that provides bearer authentication. Include it in your own API controller:

```ruby
class Api::ApplicationController < ActionController::API
  include ApiTokenAuthentication
end

class Api::ProfileController < Api::ApplicationController
  def show
    render json: { id: current_api_user.id }
  end
end
```

Clients send `Authorization: Bearer <token>`. Your actions have access to `current_api_user` and `current_api_token`. Invalid, expired, or revoked tokens receive a JSON `401`.

Token authentication does not create browser sessions. Signing out or changing a password leaves tokens active. Revocation and expiry end access. Banning or deleting the account removes its tokens. With `--security-notifications`, creation and revocation send an email.

For namespaced identities, use `Realtors::ApiTokenAuthentication` and `Realtor::ApiToken`.

## Activity

| Flag | Adds |
| --- | --- |
| `--last-seenable` | A `last_seen_at` column on users, touched at sign-in and refreshed periodically. |
| `--trackable` | An `Event` audit trail of authentication activity, browsable at `/settings/authentications/events`. Records the sign-in method used. |

## Hardening

There are many hardening measures included in every build, like rate limits and disallowing reuse of tokens. These flags are about behavior observable to the user.

| Flag | Adds |
| --- | --- |
| `--second-factor[=totp\|webauth\|sms]` | Add two-factor authentication. You can adjust which sign-in methods require a 2nd factor in the initializer. `totp` ("time-based one-time password", the default) uses an authenticator app, `webauthn` is hardware security keys (like passkeys but for 2nd factor), and `sms` is a one-time code texted to the user's phone. You may use multiple, like so: `--second-factor=totp,webauthn,sms`. Enrolling in a 2FA method will create encrypted recovery codes and show them to the user only once, and they can be regenerated if lost. `sms` needs `--phone`, and will not work with `--sms-code` since the sign-in method and the 2FA method would be exactly the same. |
| `--sudoable` | Re-require user authentication before dangerous actions. See [Sudo](#sudo). A partial template and controller class methods are included to simplify setup. Will challenge the user with an auth method based on what methods the user has available. |
| `--captchable` | A captcha (Cloudflare Turnstile is the only provider included for now) partial template is included and used inline on the unauthenticated forms: sign-in, sign-up, password reset, magic link, texted-code sign-in. Reuse on any form you want. |
| `--security-notifications` | Email users when credentials, second factors, connected accounts, contact information, sessions, or the account itself change. Requires `--email`. |

## Administration

| Flag | Adds |
| --- | --- |
| `--adminable` | Users can be site admins. Cannot be created from ActiveRecord, must be created directly in the DB. For example, `echo "UPDATE users SET admin = true …;" \| bin/rails dbconsole` |
| `--admin-dashboard` | An `/admin` area (dashboard, users, sessions). Responds with a `404` unless the user is an admin. If `--second-factor` is included, admins are held at 2FA enrollment until they enroll one. Implies `--adminable`. |
| `--bannable` | Admins can ban users temporarily or permanently. Immediately kicks the user out and locks login. |
| `--impersonatable` | Admins can impersonate other users, with the true user being accessible through `Current.true_user`. Impersonation automatically expires after 1 hour (default). Useful for support or bug investigation. Implies `--adminable`. |
| `--easy-dev-login` | **Development only.** Bypass the sign-in form and sign in as anyone in development. Use any email/phone/username. If using `--password` then the password is ignored. If not, there will be a dedicated endpoint at `POST /easy_dev_login`. Set `REQUIRE_DEV_PASSWORD` and `REQUIRE_DEV_MFA` ENV variables to use real flows. |

## Teams

| Flag | Adds |
| --- | --- |
| `--teams[=scope\|middleware\|session]` | Add `Team`, `Membership`, and team creation/selection. `scope` (default) namespaces team pages under a `/:team_id` route scope (or `/<identity>/:team_id` for a namespaced identity), allowing separate tabs to be open with different teams on the same session, and for links to be easily shareable. `middleware` does the same thing but using middleware, as seen in 37signals apps: it peels a leading `/:team_id` onto `SCRIPT_NAME`, so every route in the app carries it without being written inside a scope (not available with `--namespaced`). `session` stores the team on the session instead, so the team identifier is not in the url, but you're limited to one active team per session. A namespaced identity gets its own teams (`Merchant::Team`, `Merchant::Membership`). |

## Identity classes

You can customize the identity class used in generation.

| Flag | Adds |
| --- | --- |
| `--user-class=NAME` | Rename the generated identity (default `User`). The table, sessions, routes, controllers and config constant all derive from it. |
| `--namespaced` | Give the identity its own URL prefix and namespace. **This is required when generating a second identity** so it doesn't collide with the first. |
| `--primary-key-type=TYPE` | Primary key type for the generated migrations (e.g. `uuid`). |

Most apps will only ever need one user identity class and can utilize roles or admin flags to differentiate user types. However, if you need totally separate authentication methods or namespaces, you may run the generator again with `--namespaced` and a different `--user-class` to get a second, fully independent auth stack: its own model, table, sessions, controllers, routes, and flags.

```bash
bin/rails generate authnz_eleven --email --password --guestable
bin/rails generate authnz_eleven --email --phone --passkey --timeoutable --user-class=Realtor --namespaced
```

That gives you a `Realtor` model that signs in at `/realtor/sign_in`, `Realtors::SessionsController`,
`realtor_sign_in_path`, a `Realtor::Session` and a `Realtors::BaseController`.
It's purely additive. No file from the first run is touched.

A namespaced identity is its own portal, the way a Rails engine is. `Realtors::BaseController`
inherits `ActionController::Base`, not your `ApplicationController`, and renders
a `realtors` layout. Nothing you change in one identity's auth code reaches the other.

## Invitations

When using an invitable registration mode, you can send invitations to both emails and phone numbers if the invitee doesn't already have an account. The `User` is not created until the invitee accepts the invitation. 
If teams are enabled as well, the you can also invite existing users to a team using email or phone.

## Guests

`--guestable` adds anonymous users. A guest is a **real `User` row** (`guest: true`) with a **real session**, so they get a real `Current.user` and your existing code should work unchanged. Guests are not considered `authenticated?` though.

Opt a controller in with `allow_guest_access`:

```ruby
class CartsController < ApplicationController
  allow_guest_access

  def show
    @cart = Current.user.cart   # both authenticated users and guest users can have carts
  end
end
```

When a guest signs in or signs up, `absorb_guest` in `User::Guestable` is called from the `Authentication` concern and transfers the guest state onto the authenticated account, then destroys the guest row:

```ruby
def absorb_guest(guest)
  transaction do
    guest.cart&.update!(user: self)
    guest.destroy
  end
end
```

Guests sessions will pile up, so run the included rake task or schedule the cleanup job by uncommenting the entry in `config/recurring.yml`.

```bash
bin/rails authnz_eleven:delete_expired_guests
```

A guest's age is measured from creation, not last activity, and guests are exempt from `--timeoutable`. Their cookie persists for that lifetime, so returning visitors reuse their guest account even after closing the browser.

## Sudo

`--sudoable` generates two macros, for two different use cases:

```ruby
require_sudo only: :destroy                 # require the sudo challenge answer as a param in a single request
require_sudo_within 10.minutes              # guard a collection of routes
```

`require_sudo` is for a single dangerous action. Include the password (or webauthn credential, or
code) in a field on the form you submit. `require_sudo_within` guards a
whole section and keeps it unlocked for the window. 

A successful sudo confirmation stamps the session's `sudo_at` column. `require_sudo_within` checks that that timestamp is within the window, otherwise the user is redirected to a separate confirmation page, then back to the originally requested protected page.

Use `require_sudo_within` on pages that can safely be requested again. It redirects back to the original URL; it does not replay a submitted form or preserve an OAuth callback's provider authentication data.

Out of the box, sudo guards actions that create persistent access to the account, or that can't be undone:

- changing the email address
- changing the phone number
- adding a passkey or security key
- creating an API token
- deleting the account

Sudo only works with a password, passkey, or a TOTP/webauthn 2nd factor. Accounts that only use magic links, SMS OTPs, or logins from an Omniauth provider cannot perform a sudo and will not be asked for one.

## Configuration

`config/initializers/authentication.rb` holds every config, aliased to a top-level constant, `UserAuth` (default), so you can reference `UserAuth.session.idle_timeout`. I suggest you read that file to understand the different options. A namespaced identity gets its own config constant, for example `RealtorAuth`.

The flags you generated the build with are posted in a comment at the top of the file.

## Upgrading or transmuting

Because authentication is generated into your app, there is no automated way to change to a new version or different set of flags in the future after you have added your own code in there, like you may be able to do in some runtime auth gems. However, you can generate a new separate build with the flags you want, and point an agent at it to fix your app to use the auth system of the new one. Don't forget to do data migrations and update your UI as well. Overall this seems to be effective because the chance of the agent messing up or building something awkward is greatly diminished by the fact that it has a reference implementation, a "spec", to look at.

## Notes

- `/settings` uses the top-level `Settings` constant. If your app already
  defines one (the [`config`](https://github.com/rubyconfig/config) gem does),
  [rename it before generating](https://github.com/rubyconfig/config#configuration).
  

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests and style.

## Acknowledgments

This gem was heavily inspired by [`authentication-zero`](https://github.com/lazaronixon/authentication-zero), [`devise`](https://github.com/heartcombo/devise), and [`rodauth`](https://github.com/jeremyevans/rodauth). Thank you.

## Author

Patrick Ziller

## License

MIT, see [LICENSE.txt](LICENSE.txt).
