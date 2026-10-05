# frozen_string_literal: false

require "rails/generators/active_record"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/string/filters"
require_relative "../../authnz_eleven/version"
require_relative "../../authnz_eleven/identity"
require_relative "../../authnz_eleven/principals"

# Generates a pre-built authentication system into a Rails application.
#
# The core is DB-backed sessions, channel verification and /settings. Doors —
# --password, --magic-link, --sms-code, --omniauth, --passkey — and everything
# else is selected through flags; at least one principal and one door are required.
#
# Behavior is split into concerns rather than a fat User, and tunables live in
# the generated initializer rather than in flags.
class AuthnzElevenGenerator < Rails::Generators::Base
  include ActiveRecord::Generators::Migration

  # With this many flags, a misspelling is the likeliest way to get a build that is
  # quietly missing a feature: Thor's default is to ignore what it doesn't
  # recognise, so `--password-rotateable` would generate an app with no rotation and say
  # nothing. Refuse instead.
  check_unknown_options!

  class_option :email, type: :string, lazy_default: "required", group: "Identifier", desc: "Sign in with an email address: required (default) or optional. Add ,permanent to stop users changing it"
  class_option :phone, type: :string, lazy_default: "required", group: "Identifier", desc: "Sign in with a phone number: required (default) or optional. Add ,permanent to stop users changing it"
  class_option :username, type: :boolean, group: "Identifier", desc: "Sign in with a unique, unchangeable username"
  class_option :registration, type: :string, default: "open", enum: %w[open open-and-invites invite-only closed], group: "Identifier", desc: "Who can create an account"
  class_option :contactable, type: :boolean, default: true, group: "Identifier", desc: "Every account must have an email or phone, so you can reach them"
  class_option :verifiable, type: :boolean, default: true, group: "Identifier", desc: "Verify emails by link and phones by texted code"
  class_option :coy, type: :boolean, default: false, group: "Identifier", desc: "Respond the same whether or not an account exists for an email or phone"
  class_option :encrypted_pii, type: :boolean, group: "Identifier", desc: "Encrypt emails and phone numbers at rest"
  class_option :guestable, type: :boolean, group: "Identifier", desc: "Anonymous guest users, absorbed into the account when they sign up"

  class_option :password, type: :string, lazy_default: "required", enum: %w[required optional deferred], group: "Sign-in", desc: "Password sign-in. deferred asks for it after verification"
  class_option :magic_link, type: :boolean, group: "Sign-in", desc: "Sign in by emailed link"
  class_option :sms_code, type: :boolean, group: "Sign-in", desc: "Sign in by texted six-digit code. Needs --phone"
  class_option :passkey, type: :boolean, group: "Sign-in", desc: "Sign in with a passkey"
  class_option :omniauth, type: :boolean, group: "Sign-in", desc: "Social / SSO login via OmniAuth"

  class_option :recoverable, type: :boolean, group: "Password", desc: "Password reset by emailed link"
  class_option :pwned, type: :boolean, group: "Password", desc: "Reject passwords found in known data breaches"
  class_option :strong_passwords, type: :boolean, group: "Password", desc: "Reject weak passwords by zxcvbn score"
  class_option :deadboltable, type: :boolean, group: "Password", desc: "Shut password sign-in for a while after too many failures. Needs --password"
  class_option :password_rotatable, type: :boolean, group: "Password", desc: "Make users change their password every 90 days"
  class_option :password_historical, type: :boolean, group: "Password", desc: "Reject reuse of the last 5 passwords"

  class_option :rememberable, type: :boolean, group: "Session", desc: "A 'remember me' checkbox on password sign-in"
  class_option :timeoutable, type: :boolean, group: "Session", desc: "Sign users out after a period of inactivity"
  class_option :max_sessionable, type: :string, lazy_default: "evict", enum: %w[evict prompt], group: "Session", desc: "Cap concurrent sessions: evict the oldest (default), or prompt the user to end one"
  class_option :last_seenable, type: :boolean, group: "Session", desc: "Record when each user was last seen"
  class_option :trackable, type: :boolean, group: "Session", desc: "An audit trail of authentication activity"

  class_option :api_tokens, type: :boolean, group: "API", desc: "Personal access tokens for your own API endpoints"

  class_option :second_factor, type: :string, lazy_default: "totp", group: "Hardening", desc: "Two-factor auth: totp (default), webauthn, sms, or a comma-separated mix"
  class_option :sudoable, type: :boolean, group: "Hardening", desc: "Ask users to authenticate again before dangerous actions"
  class_option :captchable, type: :boolean, group: "Hardening", desc: "A Cloudflare Turnstile captcha on the signed-out forms"
  class_option :security_notifications, type: :boolean, group: "Hardening", desc: "Email users when security settings change. Needs --email"

  class_option :adminable, type: :boolean, group: "Admin", desc: "Users can be site admins, set in the database"
  class_option :admin_dashboard, type: :boolean, group: "Admin", desc: "An /admin area for users and sessions"
  class_option :bannable, type: :boolean, group: "Admin", desc: "Admins can ban users, temporarily or permanently"
  class_option :impersonatable, type: :boolean, group: "Admin", desc: "Admins can impersonate other users"
  class_option :easy_dev_login, type: :boolean, group: "Admin", desc: "Development only: sign in as anyone"

  class_option :teams, type: :string, lazy_default: "scope", enum: %w[scope middleware session], group: "Team", desc: "Teams and memberships. The current team lives in the URL (scope, middleware) or the session"

  class_option :user_class, type: :string, group: "Identity class", desc: "Name of the identity class (default User)"
  class_option :namespaced, type: :boolean, group: "Identity class", desc: "Its own URL prefix and namespace. Required for a second identity"
  class_option :primary_key_type, type: :string, group: "Identity class", desc: "Primary key type for the migrations, e.g. uuid"

  source_root File.expand_path("templates", __dir__)

  def validate_principal!
    return if principals.any?

    raise Rails::Generators::Error, <<~MSG.squish
      No identifier was selected. Add --email, --phone or --username.
    MSG
  end

  # Fail fast when a generated app would have no way to sign in.
  def validate_authentication_strategy!
    return if password? || magic_link? || omniauth? || passkey? || sms_code?

    raise Rails::Generators::Error, <<~MSG.squish
      No sign-in method was selected. Add --password, --magic-link, --sms-code,
      --passkey or --omniauth.
    MSG
  end

  # --second-factor names the factors an account may enroll, so an unknown one is a
  # typo that would otherwise generate a build quietly missing the factor asked for.
  def validate_second_factor!
    unknown = second_factors - %i[totp webauthn sms]

    unless unknown.empty?
      raise Rails::Generators::Error, <<~MSG.squish
        Unknown second factor#{"s" if unknown.size > 1} #{unknown.map(&:inspect).join(", ")}.
        Use totp, webauthn, sms, or a comma-separated mix like totp,webauthn.
        For passkey sign-in, use --passkey.
      MSG
    end

    return unless sms_second_factor?

    if principals.phone.nil?
      raise Rails::Generators::Error, <<~MSG.squish
        --second-factor=sms needs --phone.
      MSG
    end

    return unless sms_code?

    raise Rails::Generators::Error, <<~MSG.squish
      --sms-code and --second-factor=sms both text a code to the same phone, so
      the second text adds no security. Use one or the other.
    MSG
  end

  # A deadbolt counts failed guesses at a password, so without one there is nothing
  # to count and nothing to bar. Refused rather than ignored: silently generating
  # no deadbolt for a build that asked for one is how you end up believing you have a
  # brute-force defence that was never emitted.
  def validate_deadboltable!
    return unless options.deadboltable?
    return if password?

    raise Rails::Generators::Error, <<~MSG.squish
      --deadboltable needs --password. The other sign-in methods can't be
      guessed. To block an account entirely, use --bannable.
    MSG
  end

  def validate_coy!
    return unless coy? && !options.verifiable?

    raise Rails::Generators::Error, <<~MSG.squish
      --coy needs verification. Without it, sign-up says when an email or phone
      number is already taken. Remove --no-verifiable, or remove --coy.
    MSG
  end

  def validate_sudoable!
    return unless sudoable?
    return if sudo_bars.any?

    raise Rails::Generators::Error, <<~MSG.squish
      --sudoable needs a password, a passkey, or a totp or webauthn second
      factor to ask for. Add --password, --passkey or --second-factor.
    MSG
  end

  def validate_security_notifications!
    return unless security_notifications? && principals.email.nil?

    raise Rails::Generators::Error, <<~MSG.squish
      --security-notifications needs --email so there is somewhere to send them.
    MSG
  end

  # --password=optional means "optional because another door covers you" — the
  # sense --contactable gives --email=optional. With no other door there is
  # nothing to be optional against, and a blank field would mint an account that
  # can never sign in. Same shape as validate_email_none!, and the same reason
  # --contactable refuses a lone optional channel.
  def validate_password_optional!
    return unless password_form_optional?
    return if non_password_doors?

    raise Rails::Generators::Error, <<~MSG.squish
      --password=optional needs another sign-in method, or users who skip the
      password can't sign in. Add --passkey, --omniauth, --magic-link or
      --sms-code, or use --password.
    MSG
  end

  # --password=deferred moves the password off the sign-up form onto a second
  # page. That page must earn its place for every sign-up: it either follows a
  # channel verification, or offers a choice between a password and a passkey.
  # Otherwise it is one page's work split across two.
  def validate_password_deferred!
    return unless password_deferred?
    return if passkey?
    return if contactable? && (email_verifiable? || phone_verifiable?)

    raise Rails::Generators::Error, <<~MSG.squish
      --password=deferred asks for the password after the user verifies their
      email or phone, and with these flags not every sign-up does. Add --passkey,
      or use --password or --password=optional.
    MSG
  end

  # --sms-code texts the code to the number on the account.
  def validate_sms_code_option!
    return unless options.sms_code?

    if principals.phone.nil?
      raise Rails::Generators::Error, <<~MSG.squish
        --sms-code needs --phone.
      MSG
    end

    return unless principals.phone.optional?
    return if password? || magic_link? || omniauth? || passkey?

    raise Rails::Generators::Error, <<~MSG.squish
      --sms-code is the only sign-in method, so every account needs a phone
      number. Use --phone, or add another sign-in method.
    MSG
  end

  # --email takes a requiredness word, optionally followed by modifiers.
  def validate_email_option!
    return unless options[:email]

    return if principal_mode_valid?(options[:email])

    raise Rails::Generators::Error, <<~MSG.squish
      --email=#{options[:email]} isn't valid. Use --email, --email=optional or
      --email=required,permanent.
    MSG
  end

  # --phone mirrors --email's value guard. Omission means no phone column.
  def validate_phone_option!
    return unless options[:phone]

    return if principal_mode_valid?(options[:phone])

    raise Rails::Generators::Error, <<~MSG.squish
      --phone=#{options[:phone]} isn't valid. Use --phone, --phone=optional or
      --phone=required,permanent.
    MSG
  end

  # "permanent" removes the settings surface for a principal, so the value a row
  # is created with is the one it keeps. That only holds when the value is there
  # from the start. An optional one may arrive later, which needs the settings form.
  def validate_permanent!
    principal = principals.select(&:permanent?).find(&:optional?)
    return unless principal

    raise Rails::Generators::Error, <<~MSG.squish
      --#{principal.column}=optional,permanent isn't supported. A permanent value
      has to be given at sign-up. Use --#{principal.column}=required,permanent.
    MSG
  end

  # --no-verifiable leaves nobody having proved the address, so permanent freezes
  # whatever was typed, typo included: no reset, no magic link, no settings form.
  # Warn rather than refuse — the column stays writable, so an admin or a console
  # can still fix it, and that is the host's call to make.
  def warn_about_unverified_permanent!
    permanent = principals.select { |p| p.permanent? && !channel_verifiable?(p) }
    return if permanent.empty?

    say_status :warning, <<~MSG.squish, :yellow
      --#{permanent.map(&:column).join(" and --")}=required,permanent with --no-verifiable:
      the value is never verified, so users can't fix a typo from sign-up. Only an
      admin can.
    MSG
  end

  def validate_channel_dependencies!
    conflicts = []
    conflicts << "--recoverable needs --email." if recoverable? && principals.email.nil?
    conflicts << "--magic-link needs --email." if magic_link? && principals.email.nil?
    conflicts << "--registration=#{options[:registration]} needs --email or --phone." if invitable? && principals.channels.empty?
    return if conflicts.empty?

    raise Rails::Generators::Error, conflicts.join(" ")
  end

  # --contactable promises every account holds a channel. With TWO optional channels
  # that promise is a real record-level rule (Principals#must_be_contactable): give a
  # number or an address, either will do. With only ONE channel there is nothing for
  # "optional" to be optional against, and the promise and the flag disagree.
  #
  # Refuse rather than resolve it. Promoting the column to required would override
  # what the author wrote without saying so; leaving it alone would let the flag be
  # on while accounts hold no channel at all. Making them say which they meant is
  # the only option honest in both directions.
  def validate_contactable!
    return unless contactable?

    channels = principals.select(&:channel?)
    return if channels.size > 1 || channels.any?(&:required?)
    return if channels.empty? # A username-only build has no channel to require.

    only = channels.sole
    raise Rails::Generators::Error, <<~MSG.squish
      With --#{only.column}=optional and no #{only.type == :email ? "phone" : "email"},
      an account could have no way to be contacted. Use --#{only.column},
      add --#{only.type == :email ? "phone=optional" : "email=optional"}, or allow it
      with --no-contactable.
    MSG
  end

  # A generated identity claims a top-level Ruby constant for its model (e.g.
  # --user-class=Admin -> class Admin, app/models/admin.rb). If that constant is
  # already a namespace on disk (e.g. app/controllers/admin/ from --admin-dashboard's
  # Admin::* controllers), Zeitwerk raises at boot — far from where the mistake
  # was made. Catch it here instead. Checks what is actually on disk rather than
  # hardcoding "admin" as a reserved word, so it also catches collisions with any
  # other existing app/controllers namespace.
  def validate_no_constant_collision!
    if admin_dashboard? && identity.singular == "admin" && !identity.namespaced?
      raise Rails::Generators::Error, <<~MSG.squish
        --admin-dashboard and --user-class=Admin can't be combined: both define
        Admin. Choose a different --user-class.
      MSG
    end

    namespace_dir = in_destination("app/controllers/#{identity.singular}")
    # An empty (or nonexistent) directory defines no autoload entry, so it can't
    # actually collide — only files inside it would. Check for those, not just
    # the directory's existence, to avoid flagging harmless leftover/stray dirs.
    return if Dir.glob("#{namespace_dir}/**/*.rb").none?

    raise Rails::Generators::Error, <<~MSG.squish
      --user-class=#{identity.class_name} can't be used: app/controllers/#{identity.singular}/
      already defines a #{identity.class_name} module, which would clash with the
      #{identity.class_name} model. Choose a different --user-class.
    MSG
  end

  # A second (or later) identity must be namespaced — a run without --namespaced
  # always writes to the same shared paths (app/models/session.rb, app/models/current.rb,
  # app/controllers/application_controller.rb, ...) regardless of --user-class, so
  # a second such run collides with the incumbent identity. Catch it up front
  # with a clear message instead of Rails' per-file overwrite prompt.
  def validate_second_identity_namespaced!
    return if identity.namespaced?
    return unless File.exist?(in_destination("app/models/session.rb"))
    return if File.read(in_destination("app/models/session.rb")).include?("belongs_to :#{identity.singular}")

    raise Rails::Generators::Error, <<~MSG.squish
      This app already has an identity, so a second one must be generated
      with --namespaced. Re-run with --user-class=#{identity.class_name} --namespaced.
    MSG
  end

  def validate_middleware_teams!
    return unless middleware_teams? && identity.namespaced?

    raise Rails::Generators::Error, <<~MSG.squish
      --teams=middleware can't be used with --namespaced. Use --teams or
      --teams=session.
    MSG
  end

  def add_gems
    if password?
      if bcrypt_present?
        uncomment_lines "Gemfile", /gem "bcrypt"/
      else
        gem "bcrypt", "~> 3.1.7", comment: "Use Active Model has_secure_password [https://guides.rubyonrails.org/active_model_basics.html#securepassword]"
      end
    end

    if principals.email
      gem "valid_email2", comment: "Use valid_email2 for well-tested email syntax validation [https://github.com/micke/valid_email2]"
    end

    if phone?
      gem "phonelib", comment: "Use phonelib to parse, validate, and normalize phone numbers to E.164 [https://github.com/daddyz/phonelib]"
    end

    if omniauth?
      gem "omniauth", ">= 2.0", comment: "Use OmniAuth to support multi-provider authentication [https://github.com/omniauth/omniauth]"
    end

    if second_factor?
      gem "rotp", comment: "Use rotp for generating and validating one time passwords [https://github.com/mdp/rotp]"
      gem "rqrcode", comment: "Use rqrcode for creating and rendering QR codes into various formats [https://github.com/whomwah/rqrcode]"
    end

    if webauthn_credentials?
      gem "webauthn", comment: "Use webauthn to make Rails a conformant WebAuthn relying party [https://github.com/cedarcode/webauthn-ruby]"
    end

    if pwned?
      gem "pwned", comment: "Use Pwned to check if a password has been found in any data breach [https://github.com/philnash/pwned]"
    end

    if strong_passwords?
      gem "zxcvbn", comment: "Use zxcvbn to score password strength and reject weak passwords [https://github.com/envato/zxcvbn-ruby]"
    end
  end

  def create_configuration_files
    template "config/initializers/authentication.rb.tt", "config/initializers/#{identity.initializer_file}.rb"
    template "config/locales/authentication.en.yml.tt", "config/locales/#{identity.initializer_file}.en.yml"
    install_omniauth_initializer
    template "config/initializers/webauthn.rb.tt", "config/initializers/webauthn.rb" if webauthn_credentials? && !File.exist?(in_destination("config/initializers/webauthn.rb"))
    template "config/initializers/team_slug.rb.tt", "config/initializers/team_slug.rb" if middleware_teams?

    if principals.username
      # The forbidden-username blocklist is plain data read by the user model's
      # validation, and it's identity-free — a second --username identity reuses
      # the first writer's copy (first-writer-wins, like the captcha lib).
      copy_file "config/forbidden_usernames.txt", "config/forbidden_usernames.txt" unless File.exist?(in_destination("config/forbidden_usernames.txt"))
      copy_file "config/forbidden_usernames.LICENSE", "config/forbidden_usernames.LICENSE" unless File.exist?(in_destination("config/forbidden_usernames.LICENSE"))
    end
  end

  # Rails' stock filter list doesn't reach the columns this generator adds, so
  # they log in the clear — and since ActiveRecord::Base.filter_attributes reads
  # the same list, they print from `inspect` too.
  #
  # They go in config/initializers/filter_parameter_logging.rb rather than our own
  # initializer: that file is where someone auditing "what does this app redact?"
  # looks. It belongs to the host app, so this only appends, and only what isn't
  # already there (a re-run, or a second identity sharing a filter with the first).
  def install_parameter_filters
    names       = parameter_filters
    initializer = "config/initializers/filter_parameter_logging.rb"
    return if names.empty?

    unless File.exist?(in_destination(initializer))
      @parameter_filter_line = filter_parameters_line(names)
      return
    end

    contents = File.read(in_destination(initializer))
    names    = names.reject { |name| contents.include?(filter_regexp(name)) }
    return if names.empty?

    append_to_file initializer, <<~RUBY

      # Added by authnz_eleven: identifiers and secrets this authentication system
      # stores or receives that the list above doesn't reach. Anchored rather than
      # substring-matched (the notation the list above uses) so that, for example,
      # `uid` doesn't also swallow `uuid`, and `code` leaves unrelated names that
      # merely contain the same substring readable.
      #{filter_parameters_line(names)}
    RUBY
  end

  # One builder per identity, in its own file: a strategy's path_prefix must match
  # the prefix its callbacks are routed under, and each identity picks its providers.
  def install_omniauth_initializer
    return unless omniauth?

    template "config/initializers/omniauth.rb.tt", "config/initializers/#{identity.namespaced? ? "#{identity.singular}_omniauth" : "omniauth"}.rb"
  end

  def omniauth_path_prefix
    identity.namespaced? ? "/#{identity.path_prefix}/auth" : "/auth"
  end

  # Rails ships :null_store in test. Texted codes and magic links live in the cache
  # and fail closed on a miss, so a build with either needs a real store for its
  # own suite to pass. Throttles fail open and aren't listed.
  def configure_test_cache
    environment = "config/environments/test.rb"
    return unless sms? || magic_link?
    return unless File.read(in_destination(environment)).include?("config.cache_store = :null_store")

    gsub_file environment, "config.cache_store = :null_store", "config.cache_store = :memory_store"

    test_helper = "test/test_helper.rb"
    reset = "ActiveSupport::TestCase.setup { Rails.cache.clear }"
    return unless File.exist?(in_destination(test_helper)) && !File.read(in_destination(test_helper)).include?(reset)

    append_to_file test_helper, "\n#{reset}\n"
  end

  # Behaviour tests see deferred work done by the time the request returns. The
  # emitted account-existence parity test swaps the adapter back to prove it left.
  def configure_test_deferred_jobs
    test_helper = "test/test_helper.rb"
    inline = "AuthnzElevenDeferredJob.queue_adapter = :inline"
    return unless coy? && File.exist?(in_destination(test_helper))
    return if File.read(in_destination(test_helper)).include?(inline)

    append_to_file test_helper, "\n#{inline}\n"
  end

  # Tests answer a WebAuthn sudo bar by tapping whichever fake key @client holds.
  def configure_test_webauthn
    test_helper = "test/test_helper.rb"
    return unless webauthn_credentials? && File.exist?(in_destination(test_helper))

    require_line = %(require "webauthn/fake_client")
    append_to_file test_helper, "\n#{require_line}\n" unless File.read(in_destination(test_helper)).include?(require_line)
    assertion = "#{identity.route_scope}_sudo_assertion"
    return if !sudoable? || File.read(in_destination(test_helper)).include?("def #{assertion}")

    append_to_file test_helper, <<~RUBY

      class ActionDispatch::IntegrationTest
        def #{assertion}
          get new_#{identity.route_scope}_sudo_path(format: :json)
          @client.get(challenge: response.parsed_body.fetch("challenge"), rp_id: WebAuthn.configuration.rp_id,
                      user_verified: true).to_json
        end
      end
    RUBY
  end

  # Fixtures are written in the clear, so without this the suite stores plaintext into
  # an encrypted column and every read of it raises. Rails defaults it off, and the
  # file belongs to the host app, so only append when it isn't already set.
  def configure_fixture_encryption
    environment = "config/environments/test.rb"
    setting     = "config.active_record.encryption.encrypt_fixtures = true"
    return unless encryption? && File.exist?(in_destination(environment))
    return if File.read(in_destination(environment)).include?(setting)

    inject_into_file environment, "\n  #{setting}\n", before: /^end\b/
  end

  def create_migrations
    migration_template "migrations/create_users_migration.rb.tt", "#{db_migrate_path}/create_#{identity.table}.rb"
    migration_template "migrations/create_teams_migration.rb.tt", "#{db_migrate_path}/create_#{identity.teams_table}.rb" if teams?
    migration_template "migrations/create_memberships_migration.rb.tt", "#{db_migrate_path}/create_#{identity.memberships_table}.rb" if teams?
    migration_template "migrations/create_sessions_migration.rb.tt", "#{db_migrate_path}/create_#{identity.sessions_table}.rb"
    migration_template "migrations/create_api_tokens_migration.rb.tt", "#{db_migrate_path}/create_#{identity.api_tokens_table}.rb" if api_tokens?
    migration_template "migrations/create_events_migration.rb.tt", "#{db_migrate_path}/create_#{identity.events_table}.rb" if trackable?
    migration_template "migrations/create_recovery_codes_migration.rb.tt", "#{db_migrate_path}/create_#{identity.recovery_codes_table}.rb" if second_factor?
    migration_template "migrations/create_webauthn_credentials_migration.rb.tt", "#{db_migrate_path}/create_#{identity.webauthn_credentials_table}.rb" if webauthn_credentials?
    migration_template "migrations/create_password_histories_migration.rb.tt", "#{db_migrate_path}/create_#{identity.password_histories_table}.rb" if password_historical?
    migration_template "migrations/create_invitations_migration.rb.tt", "#{db_migrate_path}/create_#{identity.invitations_table}.rb" if invitable?
    migration_template "migrations/create_pending_registrations_migration.rb.tt", "#{db_migrate_path}/create_#{identity.pending_registrations_table}.rb" if pending_registration_model?
    migration_template "migrations/create_omniauth_identities_migration.rb.tt", "#{db_migrate_path}/create_#{identity.omniauth_identities_table}.rb" if omniauth?
    migration_template "migrations/add_guest_to_users_migration.rb.tt", "#{db_migrate_path}/add_guest_to_#{identity.table}.rb" if guestable?
  end

  def create_models
    template "models/current.rb.tt", "app/models/#{identity.current_file}.rb"
    template "models/user.rb.tt", "app/models/#{identity.singular}.rb"
    template "models/session.rb.tt", "app/models/#{identity.session_file}.rb"
    template "models/api_token.rb.tt", "app/models/#{identity.api_token_file}.rb" if api_tokens?

    template "models/concerns/principals.rb.tt", shared_concern_path(identity.principals_concern_file)
    template "models/concerns/password_policy.rb.tt", shared_concern_path(identity.password_policy_concern_file) if password?
    template "models/concerns/authenticatable.rb.tt", "app/models/#{identity.singular}/authenticatable.rb"
    template "models/concerns/password_rotatable.rb.tt", "app/models/#{identity.singular}/password_rotatable.rb" if password_rotatable?
    template "models/concerns/password_historical.rb.tt", "app/models/#{identity.singular}/password_historical.rb" if password_historical?
    template "models/concerns/recoverable.rb.tt", "app/models/#{identity.singular}/recoverable.rb" if recoverable?
    template "models/concerns/magic_linkable.rb.tt", "app/models/#{identity.singular}/magic_linkable.rb" if magic_link?
    template "models/concerns/second_factor.rb.tt", "app/models/#{identity.singular}/second_factor.rb" if second_factor?
    template "models/concerns/deadboltable.rb.tt", "app/models/#{identity.singular}/deadboltable.rb" if deadboltable?
    template "models/concerns/bannable.rb.tt", "app/models/#{identity.singular}/bannable.rb" if bannable?
    template "models/concerns/email_verifiable.rb.tt", "app/models/#{identity.singular}/email_verifiable.rb" if email_change_verification?
    template "models/concerns/phone_verifiable.rb.tt", "app/models/#{identity.singular}/phone_verifiable.rb" if phone_change_verification?
    template "models/concerns/sms_challengeable.rb.tt", "app/models/#{identity.singular}/sms_challengeable.rb" if sms?

    if trackable?
      template "models/event.rb.tt", "app/models/#{identity.event_file}.rb"
      template "models/concerns/eventable.rb.tt", shared_concern_path(identity.namespaced_class("Eventable").underscore)
    end

    template "models/recovery_code.rb.tt", "app/models/#{identity.recovery_code_file}.rb" if second_factor?
    template "models/webauthn_credential.rb.tt", "app/models/#{identity.webauthn_credential_file}.rb" if webauthn_credentials?
    template "models/password_history.rb.tt", "app/models/#{identity.password_history_file}.rb" if password_historical?

    template "models/pending_registration.rb.tt", "app/models/#{identity.pending_registration_file}.rb" if pending_registration_model?
    template "models/omniauth_identity.rb.tt", "app/models/#{identity.omniauth_identity_file}.rb" if omniauth?

    template "models/concerns/adminable.rb.tt", "app/models/#{identity.singular}/adminable.rb" if adminable?

    if teams?
      template "models/team.rb.tt", "app/models/#{identity.team_file}.rb"
      template "models/membership.rb.tt", "app/models/#{identity.membership_file}.rb"
      template "models/concerns/team_member.rb.tt", "app/models/#{identity.singular}/team_member.rb"
    end

    if invitable?
      template "models/invitation.rb.tt", "app/models/#{identity.invitation_file}.rb"
      template "models/concerns/invitable.rb.tt", "app/models/#{identity.singular}/invitable.rb"
    end

    template "models/concerns/guestable.rb.tt", "app/models/#{identity.singular}/guestable.rb" if guestable?
  end

  def create_controllers
    template "controllers/concerns/authentication.rb.tt", "app/controllers/concerns/#{identity.authentication_concern_file}.rb"
    template "controllers/concerns/api_token_authentication.rb.tt", "app/controllers/concerns/#{identity.nested_path("api_token_authentication")}.rb" if api_tokens?
    # Nested under the identity's concern rather than a flat app/controllers/concerns/
    # because it reads that identity's config, routes and sudo subject — a second
    # identity would otherwise clobber the first's copy (the EasyDevLogin shape).
    template "controllers/concerns/authentication/sudoable.rb.tt", "app/controllers/concerns/#{identity.authentication_concern_file}/sudoable.rb" if sudoable?
    template "controllers/concerns/authentication/webauthn_ceremony.rb.tt", "app/controllers/concerns/#{identity.authentication_concern_file}/webauthn_ceremony.rb" if webauthn_credentials?
    template "controllers/concerns/authentication/registering.rb.tt", "app/controllers/concerns/#{identity.authentication_concern_file}/registering.rb" if pending_registration_model?
    template "controllers/concerns/authorization.rb.tt", "app/controllers/concerns/#{identity.authorization_concern_file}.rb" if authorization?

    if captchable?
      template "controllers/concerns/captchable.rb.tt", "app/controllers/concerns/captchable.rb" unless File.exist?(in_destination("app/controllers/concerns/captchable.rb"))
      # Provider dispatch + the Turnstile strategy. app/lib is autoloaded, and the
      # Captcha namespace is where a second provider (Recaptcha, Hcaptcha) drops in.
      template "lib/captcha.rb.tt", "app/lib/captcha.rb" unless File.exist?(in_destination("app/lib/captcha.rb"))
      template "lib/captcha/turnstile.rb.tt", "app/lib/captcha/turnstile.rb" unless File.exist?(in_destination("app/lib/captcha/turnstile.rb"))
      template "lib/captcha/null.rb.tt", "app/lib/captcha/null.rb" unless File.exist?(in_destination("app/lib/captcha/null.rb"))
    end

    if sms_delivery?
      # The SMS seam, identity-free and shared: an SMS provider is app-global in
      # practice, so the first identity to need one writes these and later ones
      # reuse them. Same first-writer-wins shape as app/lib/captcha.rb, and the
      # same caveat — sms.rb bakes in its writer's config namespace. Keep the two
      # seams consistent if that coupling ever gets a cleaner resolution.
      template "lib/sms.rb.tt", "app/lib/sms.rb" unless File.exist?(in_destination("app/lib/sms.rb"))
      template "lib/sms/twilio.rb.tt", "app/lib/sms/twilio.rb" unless File.exist?(in_destination("app/lib/sms/twilio.rb"))
      template "lib/sms/log.rb.tt", "app/lib/sms/log.rb" unless File.exist?(in_destination("app/lib/sms/log.rb"))
      template "jobs/sms_delivery_job.rb.tt", "app/jobs/sms_delivery_job.rb" unless File.exist?(in_destination("app/jobs/sms_delivery_job.rb"))
    end

    if easy_dev_login?
      if password?
        # A password form already collects an email, so the shortcut piggybacks
        # on it (type any email, password ignored) — no dedicated endpoint needed.
        template "controllers/concerns/authentication/easy_dev_login.rb.tt", "app/controllers/concerns/#{identity.authentication_concern_file}/easy_dev_login.rb"
      else
        # Passwordless: there's no credential form to ride, so ship an explicit
        # dev-only endpoint the email field on the sign-in page posts to.
        template "controllers/users/easy_dev_logins_controller.rb.tt", "app/controllers/#{identity.controller_module}/easy_dev_logins_controller.rb"
      end
    end

    if identity.namespaced?
      # A namespaced identity never touches the shared ApplicationController — its
      # authentication concern (and Authorization/Captchable, if present) is
      # wired into its own BaseController instead, so a second identity's
      # inclusion can never collide with the first's.
      template "controllers/base_controller.rb.tt", "app/controllers/#{identity.base_controller_file}.rb"
    else
      inject_into_class "app/controllers/application_controller.rb", "ApplicationController" do
        # Authentication first so the session is resumed before Authorization's
        # gates run; Authorization's before_actions register after and run after.
        includes = "  include #{identity.authentication_concern}\n"
        includes += "  include #{identity.authorization_concern}\n" if authorization?
        includes += "  include Captchable\n" if captchable?
        "#{includes}\n"
      end
    end

    template "controllers/users/sessions_controller.rb.tt", "app/controllers/#{identity.controller_module}/sessions_controller.rb"
    template "controllers/users/registrations_controller.rb.tt", "app/controllers/#{identity.controller_module}/registrations_controller.rb" if typed_registration?
    template "controllers/users/password_resets_controller.rb.tt", "app/controllers/#{identity.controller_module}/password_resets_controller.rb" if recoverable?
    template "controllers/users/magic_link_controller.rb.tt", "app/controllers/#{identity.controller_module}/magic_link_controller.rb" if magic_link?
    template "controllers/users/sudos_controller.rb.tt", "app/controllers/#{identity.controller_module}/sudos_controller.rb" if sudoable?
    template "controllers/users/omniauth_controller.rb.tt", "app/controllers/#{identity.controller_module}/omniauth_controller.rb" if omniauth?
    template "controllers/users/omniauth/registrations_controller.rb.tt", "app/controllers/#{identity.controller_module}/omniauth/registrations_controller.rb" if omniauth_registration?
    template "controllers/users/passkeys/sessions_controller.rb.tt", "app/controllers/#{identity.controller_module}/passkeys/sessions_controller.rb" if passkey?
    template "controllers/users/sms_sessions_controller.rb.tt", "app/controllers/#{identity.controller_module}/sms_sessions_controller.rb" if sms_code?
    template "controllers/users/registrations/phone_verifications_controller.rb.tt", "app/controllers/#{identity.controller_module}/registrations/phone_verifications_controller.rb" if phone_gated_registration?

    if second_factor?
      # Recovery codes back whichever factors the build has, so they are the one
      # piece that follows second_factor? rather than a particular factor.
      template "controllers/users/multi_factor_authentication/challenge/recovery_codes_controller.rb.tt", "app/controllers/#{identity.controller_module}/multi_factor_authentication/challenge/recovery_codes_controller.rb"
      template "controllers/users/multi_factor_authentication/challenge/totps_controller.rb.tt", "app/controllers/#{identity.controller_module}/multi_factor_authentication/challenge/totps_controller.rb" if totp?
      template "controllers/users/multi_factor_authentication/challenge/security_keys_controller.rb.tt", "app/controllers/#{identity.controller_module}/multi_factor_authentication/challenge/security_keys_controller.rb" if security_keys?
      template "controllers/users/multi_factor_authentication/challenge/sms_controller.rb.tt", "app/controllers/#{identity.controller_module}/multi_factor_authentication/challenge/sms_controller.rb" if sms_second_factor?
    end

    template "controllers/settings_controller.rb.tt", "app/controllers/#{identity.settings_controller_file}.rb"
    template "controllers/settings/dashboard_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/dashboard_controller.rb"
    template "controllers/settings/passwords_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/passwords_controller.rb" if password?
    template "controllers/settings/emails_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/emails_controller.rb" if email_changeable?
    template "controllers/settings/phones_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/phones_controller.rb" if phone_changeable?
    template "controllers/settings/email_verifications_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/email_verifications_controller.rb" if email_change_verification?
    template "controllers/users/email_verifications_controller.rb.tt", "app/controllers/#{identity.controller_module}/email_verifications_controller.rb" if email_change_verification?
    template "erb/users/email_verifications/show.html.erb.tt", "app/views/#{identity.controller_module}/email_verifications/show.html.erb" if email_change_verification?
    template "controllers/users/registrations/email_verifications_controller.rb.tt", "app/controllers/#{identity.controller_module}/registrations/email_verifications_controller.rb" if email_gated_registration?
    template "controllers/settings/phone_verifications_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/phone_verifications_controller.rb" if phone_change_verification?
    template "controllers/settings/sessions_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/sessions_controller.rb"
    template "controllers/settings/api_tokens_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/api_tokens_controller.rb" if api_tokens?
    template "controllers/settings/users_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/users_controller.rb"
    template "controllers/settings/passkeys_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/passkeys_controller.rb" if passkey?
    template "controllers/settings/omniauth_identities_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/omniauth_identities_controller.rb" if omniauth?
    template "controllers/users/credential_enrollments_controller.rb.tt", "app/controllers/#{identity.controller_module}/credential_enrollments_controller.rb" if registration_credential_page?
    template "controllers/users/credential_enrollments/passwords_controller.rb.tt", "app/controllers/#{identity.controller_module}/credential_enrollments/passwords_controller.rb" if pre_account_password_enrollment?
    template "controllers/users/credential_enrollments/passkeys_controller.rb.tt", "app/controllers/#{identity.controller_module}/credential_enrollments/passkeys_controller.rb" if pre_account_passkey_enrollment?

    if second_factor?
      template "controllers/settings/multi_factor_authentication/recovery_codes_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/multi_factor_authentication/recovery_codes_controller.rb"
      template "controllers/settings/multi_factor_authentication/authenticators_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/multi_factor_authentication/authenticators_controller.rb" if totp?
      template "controllers/settings/multi_factor_authentication/security_keys_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/multi_factor_authentication/security_keys_controller.rb" if security_keys?
      template "controllers/settings/multi_factor_authentication/sms_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/multi_factor_authentication/sms_controller.rb" if sms_second_factor?
    end

    if trackable?
      template "controllers/settings/authentications/events_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/authentications/events_controller.rb"
    end

    if admin_dashboard?
      template "controllers/admin_controller.rb.tt", "app/controllers/#{identity.nested_path("admin_controller")}.rb"
      template "controllers/admin/dashboard_controller.rb.tt", "app/controllers/#{identity.nested_path("admin")}/dashboard_controller.rb"
      template "controllers/admin/users_controller.rb.tt", "app/controllers/#{identity.nested_path("admin")}/users_controller.rb"
      template "controllers/admin/sessions_controller.rb.tt", "app/controllers/#{identity.nested_path("admin")}/sessions_controller.rb"

      # Deliberately outside the admin area: ending impersonation is the one part
      # of the flow that must work while the admin area is shut.
      template "controllers/impersonations_controller.rb.tt", "app/controllers/#{identity.nested_path("impersonations_controller")}.rb" if impersonatable?
    end

    if teams?
      template "controllers/teams_controller.rb.tt", "app/controllers/#{identity.nested_path("teams_controller")}.rb"
      template "controllers/active_teams_controller.rb.tt", "app/controllers/#{identity.nested_path("active_teams_controller")}.rb" if session_carries_team?
    end

    if invitable?
      template "controllers/invitations_controller.rb.tt", "app/controllers/#{identity.nested_path("invitations_controller")}.rb"
      template "erb/invitations/show.html.erb.tt", "app/views/#{identity.nested_path("invitations")}/show.html.erb" if teams?
      template "controllers/settings/invitations_controller.rb.tt", "app/controllers/#{identity.settings_path_prefix}/invitations_controller.rb"
    end
  end

  def create_mailers
    template "mailers/user_mailer.rb.tt", "app/mailers/#{identity.mailer_file}.rb" if sends_email?
    return unless sends_email? && !File.exist?(in_destination("app/jobs/authnz_eleven_mail_delivery_job.rb"))

    template "jobs/authnz_eleven_mail_delivery_job.rb.tt", "app/jobs/authnz_eleven_mail_delivery_job.rb"
  end

  def create_deferred_job
    return unless coy? && !File.exist?(in_destination("app/jobs/authnz_eleven_deferred_job.rb"))

    template "jobs/authnz_eleven_deferred_job.rb.tt", "app/jobs/authnz_eleven_deferred_job.rb"
  end

  def install_javascript
    return unless webauthn_credentials?

    template "javascript/controllers/webauthn_controller.js.tt", "app/javascript/controllers/webauthn_controller.js"
    run "bin/importmap pin @rails/request.js" if importmaps?
  end

  def create_tasks
    task_path = identity.namespaced? ? "lib/tasks/authnz_eleven_#{identity.singular}.rake" : "lib/tasks/authnz_eleven.rake"
    template "tasks/authnz_eleven.rake.tt", task_path if guestable? || timeoutable? || pending_registration_model?
  end

  # Drop commented Solid Queue schedules for the sweeps next to whatever recurring
  # tasks the app already has. Only touch the file if it exists (no Solid Queue,
  # no file — the rake tasks + post-install note still cover it), and keep them
  # commented so they never collide with the app's real schedule. Each block is
  # guarded independently so re-running the generator, or adding a flag later,
  # appends only what is missing.
  def schedule_recurring_tasks
    return unless timeoutable? || guestable? || pending_registration_model?
    return unless File.exist?("config/recurring.yml")

    existing = File.read("config/recurring.yml")

    if pending_registration_model? && !existing.include?("delete_expired_pending_registrations")
      append_to_file "config/recurring.yml", <<~YAML

        #   delete_expired_pending_registrations:
        #     command: "#{identity.pending_registration_class}.expired.destroy_all"
        #     schedule: every day at 2am
      YAML
    end

    if timeoutable? && !existing.include?("delete_timed_out_sessions")
      append_to_file "config/recurring.yml", <<~YAML

        #   delete_timed_out_sessions:
        #     command: "#{identity.session_class}.timed_out.delete_all"
        #     schedule: every day at 3am
      YAML
    end

    return unless guestable?
    return if existing.include?("delete_expired_guests")

    append_to_file "config/recurring.yml", <<~YAML

      #   delete_expired_guests:
      #     command: "#{identity.class_name}.expired_guests.find_each(&:destroy)"
      #     schedule: every day at 4am
    YAML
  end

  def create_tests
    template "test_unit/fixtures/users.yml.tt", "test/fixtures/#{identity.table}.yml"
    template "test_unit/mailers/user_mailer_test.rb.tt", "test/mailers/#{identity.mailer_file}_test.rb" if sends_email?

    if teams?
      template "test_unit/fixtures/teams.yml.tt", "test/fixtures/#{identity.team_file.pluralize}.yml"
      template "test_unit/fixtures/memberships.yml.tt", "test/fixtures/#{identity.membership_file.pluralize}.yml"
    end

    template "test_unit/controllers/users/sessions_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/sessions_controller_test.rb"
    template "test_unit/controllers/account_existence_parity_test.rb.tt", "test/controllers/#{identity.controller_module}/account_existence_parity_test.rb" if coy?
    template "test_unit/controllers/session_lifecycle_test.rb.tt", "test/controllers/#{identity.controller_module}/session_lifecycle_test.rb" if timeoutable? || rememberable? || last_seenable? || max_sessionable?
    template "test_unit/controllers/security_notifications_test.rb.tt", "test/controllers/#{identity.controller_module}/security_notifications_test.rb" if security_notifications?
    template "test_unit/controllers/settings/api_tokens_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/api_tokens_controller_test.rb" if api_tokens?
    template "test_unit/models/api_token_test.rb.tt", "test/models/#{identity.api_token_file}_test.rb" if api_tokens?
    template "test_unit/controllers/api_token_authentication_test.rb.tt", "test/controllers/#{identity.controller_module}/api_token_authentication_test.rb" if api_tokens?
    template "test_unit/controllers/credential_enrollment_test.rb.tt", "test/controllers/#{identity.controller_module}/credential_enrollment_test.rb" if credential_staged_registration?
    template "test_unit/controllers/passkey_ceremony_test.rb.tt", "test/controllers/#{identity.controller_module}/passkey_ceremony_test.rb" if passkey?
    template "test_unit/controllers/security_key_ceremony_test.rb.tt", "test/controllers/#{identity.controller_module}/security_key_ceremony_test.rb" if security_keys?
    template "test_unit/controllers/password_rotation_test.rb.tt", "test/controllers/#{identity.controller_module}/password_rotation_test.rb" if password_rotatable?
    template "test_unit/models/password_history_test.rb.tt", "test/models/#{identity.password_history_file}_reuse_test.rb" if password_historical?
    template "test_unit/models/sms_challengeable_test.rb.tt", "test/models/#{identity.singular}/sms_challengeable_test.rb" if sms?
    template "test_unit/models/session_test.rb.tt", "test/models/#{identity.session_file}_test.rb" if timeoutable?
    template "test_unit/controllers/users/registrations_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/registrations_controller_test.rb" if typed_registration?
    template "test_unit/controllers/users/password_resets_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/password_resets_controller_test.rb" if recoverable?
    template "test_unit/controllers/users/magic_link_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/magic_link_controller_test.rb" if magic_link?
    template "test_unit/controllers/users/sudos_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/sudos_controller_test.rb" if sudoable?
    template "test_unit/controllers/users/omniauth_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/omniauth_controller_test.rb" if omniauth?
    template "test_unit/controllers/settings/omniauth_identities_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/omniauth_identities_controller_test.rb" if omniauth?
    template "test_unit/controllers/users/multi_factor_authentication/challenge_test.rb.tt", "test/controllers/#{identity.controller_module}/multi_factor_authentication/challenge_test.rb" if second_factor?
    template "test_unit/controllers/settings/email_verifications_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/email_verifications_controller_test.rb" if email_change_verification?
    template "test_unit/controllers/users/email_verifications_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/email_verifications_controller_test.rb" if email_change_verification?
    template "test_unit/controllers/users/registrations/email_verifications_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/registrations/email_verifications_controller_test.rb" if email_gated_registration?
    template "test_unit/controllers/settings/phone_verifications_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/phone_verifications_controller_test.rb" if phone_change_verification?
    template "test_unit/controllers/users/sms_sessions_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/sms_sessions_controller_test.rb" if sms_code?
    template "test_unit/controllers/users/registrations/phone_verifications_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/registrations/phone_verifications_controller_test.rb" if phone_gated_registration?

    # Authenticated-area tests read Current.user, which now resolves for every
    # identity (each namespaced session aliases its principal to :user — see
    # models/session.rb.tt), so these ship for namespaced identities too.
    template "test_unit/controllers/settings/management_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/management_test.rb"
    template "test_unit/controllers/settings/authentications/events_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/authentications/events_controller_test.rb" if trackable?
    template "test_unit/controllers/settings/multi_factor_authentication/management_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/multi_factor_authentication/management_test.rb" if second_factor?

    if invitable?
      template "test_unit/controllers/invitations_controller_test.rb.tt", "test/controllers/#{identity.nested_path("invitations_controller_test")}.rb"
      template "test_unit/controllers/settings/invitations_controller_test.rb.tt", "test/controllers/#{identity.settings_path_prefix}/invitations_controller_test.rb"
    end

    template "test_unit/controllers/teams_controller_test.rb.tt", "test/controllers/#{identity.nested_path("teams_controller_test")}.rb" if teams?

    if admin_dashboard?
      template "test_unit/controllers/admin/access_test.rb.tt", "test/controllers/#{identity.nested_path("admin")}/access_test.rb"
      template "test_unit/controllers/admin/multi_factor_authentication_test.rb.tt", "test/controllers/#{identity.nested_path("admin")}/multi_factor_authentication_test.rb" if second_factor?
    end

    template "test_unit/models/user/guestable_test.rb.tt", "test/models/#{identity.singular}/guestable_test.rb" if guestable?
    template "test_unit/models/user/sign_in_methods_test.rb.tt", "test/models/#{identity.singular}/sign_in_methods_test.rb" if removable_credentials?
    template "test_unit/models/user/recovery_codes_test.rb.tt", "test/models/#{identity.singular}/recovery_codes_test.rb" if both_second_factors?
    template "test_unit/controllers/guest_access_test.rb.tt", "test/controllers/#{identity.controller_module}/guest_access_test.rb" if guestable?
    template "test_unit/models/user_test.rb.tt", "test/models/#{identity.singular}_test.rb"
    template "test_unit/controllers/users/omniauth/registrations_controller_test.rb.tt", "test/controllers/#{identity.controller_module}/omniauth/registrations_controller_test.rb" if omniauth_registration?
  end

  def create_views
    template "erb/user_mailer/registration_email_verification.html.erb.tt", "app/views/#{identity.mailer_file}/registration_email_verification.html.erb" if email_gated_registration?
    template "erb/user_mailer/email_change_verification.html.erb.tt", "app/views/#{identity.mailer_file}/email_change_verification.html.erb" if email_change_verification?
    template "erb/user_mailer/password_reset.html.erb.tt", "app/views/#{identity.mailer_file}/password_reset.html.erb" if recoverable?
    template "erb/user_mailer/magic_link.html.erb.tt", "app/views/#{identity.mailer_file}/magic_link.html.erb" if magic_link?
    template "erb/user_mailer/invitation.html.erb.tt", "app/views/#{identity.mailer_file}/invitation.html.erb" if email_invitable?
    template "erb/user_mailer/security_notification.html.erb.tt", "app/views/#{identity.mailer_file}/security_notification.html.erb" if security_notifications?

    template "erb/shared/_captcha.html.erb.tt", "app/views/shared/_captcha.html.erb" if captchable? && !File.exist?(in_destination("app/views/shared/_captcha.html.erb"))
    template "erb/shared/_authnz_eleven_sudo_challenge.html.erb.tt", partial_file(identity.sudo_partial) if sudoable?

    template "erb/users/sessions/new.html.erb.tt", "app/views/#{identity.controller_module}/sessions/new.html.erb"
    template "erb/users/registrations/new.html.erb.tt", "app/views/#{identity.controller_module}/registrations/new.html.erb" if typed_registration?
    template "erb/users/omniauth/registrations/new.html.erb.tt", "app/views/#{identity.controller_module}/omniauth/registrations/new.html.erb" if omniauth_registration?
    template "erb/users/password_resets/new.html.erb.tt", "app/views/#{identity.controller_module}/password_resets/new.html.erb" if recoverable?
    template "erb/users/password_resets/edit.html.erb.tt", "app/views/#{identity.controller_module}/password_resets/edit.html.erb" if recoverable?
    if magic_link?
      template "erb/users/magic_link/new.html.erb.tt", "app/views/#{identity.controller_module}/magic_link/new.html.erb"
      template "erb/users/magic_link/edit.html.erb.tt", "app/views/#{identity.controller_module}/magic_link/edit.html.erb"
    end
    if sms_code?
      template "erb/users/sms_sessions/new.html.erb.tt", "app/views/#{identity.controller_module}/sms_sessions/new.html.erb"
      template "erb/users/sms_sessions/edit.html.erb.tt", "app/views/#{identity.controller_module}/sms_sessions/edit.html.erb"
    end
    template "erb/users/registrations/phone_verifications/new.html.erb.tt", "app/views/#{identity.controller_module}/registrations/phone_verifications/new.html.erb" if phone_gated_registration?
    if email_gated_registration?
      template "erb/users/registrations/email_verifications/new.html.erb.tt", "app/views/#{identity.controller_module}/registrations/email_verifications/new.html.erb"
      template "erb/users/registrations/email_verifications/show.html.erb.tt", "app/views/#{identity.controller_module}/registrations/email_verifications/show.html.erb"
    end
    template "erb/users/sudos/new.html.erb.tt", "app/views/#{identity.controller_module}/sudos/new.html.erb" if sudoable?

    if second_factor?
      template "erb/users/multi_factor_authentication/challenge/recovery_codes/new.html.erb.tt", "app/views/#{identity.controller_module}/multi_factor_authentication/challenge/recovery_codes/new.html.erb"
      template "erb/users/multi_factor_authentication/challenge/totps/new.html.erb.tt", "app/views/#{identity.controller_module}/multi_factor_authentication/challenge/totps/new.html.erb" if totp?
      template "erb/users/multi_factor_authentication/challenge/security_keys/new.html.erb.tt", "app/views/#{identity.controller_module}/multi_factor_authentication/challenge/security_keys/new.html.erb" if security_keys?
      template "erb/users/multi_factor_authentication/challenge/sms/new.html.erb.tt", "app/views/#{identity.controller_module}/multi_factor_authentication/challenge/sms/new.html.erb" if sms_second_factor?
    end

    template "erb/settings/dashboard/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/dashboard/index.html.erb"
    template "erb/settings/passwords/edit.html.erb.tt", "app/views/#{identity.settings_path_prefix}/passwords/edit.html.erb" if password?
    template "erb/settings/emails/edit.html.erb.tt", "app/views/#{identity.settings_path_prefix}/emails/edit.html.erb" if email_changeable?
    template "erb/settings/phones/edit.html.erb.tt", "app/views/#{identity.settings_path_prefix}/phones/edit.html.erb" if phone_changeable?
    template "erb/settings/phone_verifications/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/phone_verifications/new.html.erb" if phone_change_verification?
    template "erb/settings/sessions/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/sessions/index.html.erb"
    template "erb/settings/api_tokens/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/api_tokens/index.html.erb" if api_tokens?
    template "erb/settings/api_tokens/create.html.erb.tt", "app/views/#{identity.settings_path_prefix}/api_tokens/create.html.erb" if api_tokens?
    template "erb/settings/users/show.html.erb.tt", "app/views/#{identity.settings_path_prefix}/users/show.html.erb"

    if passkey?
      template "erb/settings/passkeys/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/passkeys/index.html.erb"
      template "erb/settings/passkeys/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/passkeys/new.html.erb"
      template "erb/settings/passkeys/edit.html.erb.tt", "app/views/#{identity.settings_path_prefix}/passkeys/edit.html.erb"
    end

    if omniauth?
      template "erb/settings/omniauth_identities/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/omniauth_identities/index.html.erb"
    end

    template "erb/users/credential_enrollments/show.html.erb.tt", "app/views/#{identity.controller_module}/credential_enrollments/show.html.erb" if registration_credential_page?
    template "erb/users/credential_enrollments/passwords/new.html.erb.tt", "app/views/#{identity.controller_module}/credential_enrollments/passwords/new.html.erb" if pre_account_password_enrollment?
    template "erb/users/credential_enrollments/passkeys/new.html.erb.tt", "app/views/#{identity.controller_module}/credential_enrollments/passkeys/new.html.erb" if pre_account_passkey_enrollment?

    if second_factor?
      template "erb/settings/multi_factor_authentication/recovery_codes/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/recovery_codes/index.html.erb"
      template "erb/settings/multi_factor_authentication/recovery_codes/create.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/recovery_codes/create.html.erb"
      template "erb/settings/multi_factor_authentication/authenticators/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/authenticators/new.html.erb" if totp?
      template "erb/settings/multi_factor_authentication/sms/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/sms/new.html.erb" if sms_second_factor?

      if security_keys?
        template "erb/settings/multi_factor_authentication/security_keys/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/security_keys/index.html.erb"
        template "erb/settings/multi_factor_authentication/security_keys/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/security_keys/new.html.erb"
        template "erb/settings/multi_factor_authentication/security_keys/edit.html.erb.tt", "app/views/#{identity.settings_path_prefix}/multi_factor_authentication/security_keys/edit.html.erb"
      end
    end

    if trackable?
      template "erb/settings/authentications/events/index.html.erb.tt", "app/views/#{identity.settings_path_prefix}/authentications/events/index.html.erb"
    end

    if admin_dashboard?
      template "erb/admin/dashboard/index.html.erb.tt", "app/views/#{identity.nested_path("admin")}/dashboard/index.html.erb"
      template "erb/admin/users/index.html.erb.tt", "app/views/#{identity.nested_path("admin")}/users/index.html.erb"
      template "erb/admin/users/show.html.erb.tt", "app/views/#{identity.nested_path("admin")}/users/show.html.erb"
      template "erb/admin/sessions/index.html.erb.tt", "app/views/#{identity.nested_path("admin")}/sessions/index.html.erb"
    end

    if teams?
      template "erb/teams/index.html.erb.tt", "app/views/#{identity.nested_path("teams")}/index.html.erb"
      template "erb/teams/new.html.erb.tt", "app/views/#{identity.nested_path("teams")}/new.html.erb"
      template "erb/teams/show.html.erb.tt", "app/views/#{identity.nested_path("teams")}/show.html.erb" if scope_teams?
    end

    if invitable?
      template "erb/settings/invitations/new.html.erb.tt", "app/views/#{identity.settings_path_prefix}/invitations/new.html.erb"
    end
  end

  # The signed-in/out chrome (Settings, Sign out, the doors) so a fresh install is
  # navigable without the host app writing a header first. Every identity gets its
  # own partial. The default identity's goes into the application layout; a namespaced
  # identity is a separate portal, like an engine, so it gets its own layout copied
  # from the application one with its own nav in place of the default's. A layout
  # is edited only when it's still the stock Rails default, so a customized one is
  # never touched — we print a one-line note instead.
  def install_navigation
    partial = partial_file(identity.nav_partial)
    template "erb/shared/_authnz_eleven_nav.html.erb.tt", partial unless File.exist?(in_destination(partial))

    application_layout = in_destination("app/views/layouts/application.html.erb")
    layout             = "app/views/layouts/#{identity.namespaced? ? identity.controller_module : "application"}.html.erb"
    render_line        = %(<%= render "#{identity.nav_partial}" %>)

    unless File.exist?(application_layout)
      @navigation_render_line = render_line
      return
    end

    unless File.exist?(in_destination(layout))
      create_file layout, File.read(application_layout).sub(%(<%= render "shared/authnz_eleven_nav" %>), render_line)
    end

    contents = File.read(in_destination(layout))
    if contents.include?(render_line)
      # Already wired (a re-run); leave it be.
    elsif contents.match?(%r{<body>\s*<%=\s*yield\s*%>\s*</body>}m)
      # Stock Rails layout — safe to drop the render in right after <body>.
      inject_into_file layout, "\n    #{render_line}", after: "<body>"
    else
      # Customized layout: don't touch it, tell them where to add the line.
      @navigation_render_line = render_line
    end
  end

  def add_routes
    route(identity.namespaced? ? namespaced_route_block : route_block)
  end

  # The first thing anyone sees, so it stays a checklist: what must happen before
  # the app runs, then what to know before it ships. Everything explanatory — how
  # the deadbolt behaves, what a guest is, which tunables exist — lives in the
  # README and the initializer, which is where someone looks for it a week later.
  def show_post_install
    return unless behavior == :invoke

    say "\nauthnz_eleven installed.", :green

    say "\nNext steps:", :green
    next_steps.each_with_index { |(text, *lines), index| say_item("#{index + 1}.", text, lines) }

    warnings = ship_warnings
    unless warnings.empty?
      say "\nBefore you ship:", :yellow
      warnings.each { |warning| say_item("*", warning, [], :yellow) }
    end

    say "\n  Config:        config/initializers/#{identity.initializer_file}.rb"
    say "  Start reading: app/controllers/concerns/#{identity.authentication_concern_file}.rb\n"
  end

  private

  # ---------------------------------------------------------------------------
  # Post-install output
  #
  # The two lists show_post_install prints, and the wrapper that renders them.
  # ---------------------------------------------------------------------------

  # Sentences are wrapped; the lines under them (commands, env vars, code) are
  # printed whole on their own rows so they can be found and copied.
  def say_item(marker, text, lines, color = nil)
    indent = " " * (marker.length + 3)
    rows   = [+"  #{marker} "]

    text.split.each do |word|
      rows << indent.dup if rows.last.length + word.length > 78
      rows.last << word << " "
    end

    rows.each { |row| say row.rstrip, color }
    lines.each { |line| say "#{indent}  #{line}", :cyan }
  end

  # What has to happen before the generated app runs, in the order you hit it.
  # Each step is a sentence followed by the lines to type or paste.
  def next_steps
    [
      (["Install the new gems.", "bundle install"] if gem_dependencies?),
      ["Run the migrations.", "bin/rails db:migrate"],
      ["Add a root route. Generated redirects use root_path."],
      (["Make sure Action Mailer can deliver in each environment, with default_url_options set."] if sends_email?),
      (["Use a shared production cache across all app processes. Missing cache entries invalidate sign-in links and texted codes."] if magic_link? || sms?),
      (encryption_step if encryption?),
      (["Set the WebAuthn origin and relying-party ID for each environment.", "config/initializers/webauthn.rb"] if webauthn_credentials?),
      (["Add your Cloudflare Turnstile keys to credentials for production (or set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY).", "turnstile:", "  site_key: ...", "  secret_key: ..."] if captchable?),
      (["Add your Twilio keys to credentials for production (or set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_MESSAGING_SERVICE_SID). Until then, texts go to the Rails log.", "twilio:", "  account_sid: ...", "  auth_token: ...", "  messaging_service_sid: ..."] if sms_delivery?),
      (["Your layout isn't the stock one, so add the navigation partial yourself:", @navigation_render_line] if @navigation_render_line),
      (["Keep identifiers out of your logs. You have no filter_parameter_logging.rb, so add this to an initializer:", @parameter_filter_line] if @parameter_filter_line),
      (["Add allow_guest_access to the controllers guests may use, and fill in #{identity.class_name}::Guestable#absorb_guest."] if guestable?),
      (sweep_step if sweep_tasks.any?)
    ].compact
  end

  def encryption_step
    ["Create encryption keys and paste them into each credentials file you deploy with. Losing them loses #{encrypted_columns_phrase}.",
     "bin/rails db:encryption:init",
     "bin/rails credentials:edit"]
  end

  def sweep_tasks
    [
      ("delete_expired_pending_registrations" if pending_registration_model?),
      ("delete_timed_out_sessions" if timeoutable?),
      ("delete_expired_guests" if guestable?)
    ].compact
  end

  def sweep_step
    scheduled = " Commented entries for them are in config/recurring.yml." if File.exist?("config/recurring.yml")
    ["Schedule these cleanup tasks. Nothing deletes expired rows for you.#{scheduled}",
     *sweep_tasks.map { |task| "bin/rails #{identity.rake_task(task)}" }]
  end

  # Risks this build can actually produce, one sentence of consequence each.
  # A feature that merely deserves explaining doesn't belong here.
  def ship_warnings
    [
      ("There is no account recovery, so a user who loses their credential is locked out. Add --recoverable, --magic-link or --sms-code." unless recovery_path?),
      ("Only configure OmniAuth providers that verify email addresses. Their addresses are trusted, so one that doesn't verify lets a stranger claim someone else's address." if omniauth? && email_verifiable?),
      (email_optional_warning if principals.email&.optional?),
      *sms_warnings
    ].compact
  end

  # Worth saying only where it bites: an account with no address either can't
  # sign in at all, or can't be recovered by the flows this build has.
  def email_optional_warning
    return "Email is optional and is your only identifier, so users who skip it can't sign in. Add --username or a required --phone." if login_principals.all? { |p| p.type == :email }

    "Email is optional, so password reset and magic links can't reach some users." if recoverable? || magic_link?
  end

  def sms_warnings
    return [] unless sms_delivery?

    [
      ("Phone numbers aren't verified (--no-verifiable), so anyone can register a number they don't own and lock out its real owner." if sms_code? && !phone_verifiable?),
      ("There is no captcha. --captchable adds one to the signed-out forms, the main brake on bots." unless captchable?),
      ("Also offer an authenticator app or passkey if you have compliance requirements. NIST SP 800-63B restricts SMS." if sms_only_authenticator?)
    ].compact
  end

  def sms_only_authenticator?
    (sms_code? || sms_second_factor?) && !(passkey? || totp? || security_keys?)
  end

  # What the encryption step names as covered.
  def encrypted_columns_phrase
    columns = encrypted_pii? ? principals.select(&:channel?).map(&:column) : []
    columns.push("totp_secret") if totp?
    columns.to_sentence
  end

  # Whether any flow in this build sends mail — the same set of conditions the
  # mailer template guards its methods with.
  def sends_email?
    email_gated_registration? || email_change_verification? || recoverable? ||
      magic_link? || email_invitable? || security_notifications?
  end

  # ---------------------------------------------------------------------------
  # Generator plumbing
  # ---------------------------------------------------------------------------

  # A --email / --phone value: one requiredness word, optionally followed by
  # "permanent". Principals.split_mode does the splitting; this only says whether
  # what it found is what a principal accepts.
  def principal_mode_valid?(value)
    requiredness, modifiers = AuthnzEleven::Principals.split_mode(value)

    AuthnzEleven::Principals::REQUIREDNESS.include?(requiredness) &&
      (modifiers.empty? || AuthnzEleven::Principals.permanent?(modifiers))
  end

  # The invocation that produced this build, stamped into the initializer so an
  # app can say what it was generated from years later. Rebuilt from the flags
  # rather than read off ARGV, so it is the same command whether the generator
  # was run from the command line or invoked in a test.
  #
  # Only flags that moved off their default are named: a default-valued flag
  # would be noise, and re-running the printed command has to mean the same
  # thing under the version it names.
  def generation_command
    flags = self.class.class_options.except(*Rails::Generators::Base.class_options.keys).filter_map do |name, option|
      value = options[name.to_s]
      generation_flag(name, value) unless value == option.default
    end
    ["bin/rails generate authnz_eleven", *flags]
  end

  def generation_flag(name, value)
    dashed = name.to_s.tr("_", "-")
    case value
    when true  then "--#{dashed}"
    when false then "--no-#{dashed}"
    else            "--#{dashed}=#{value}"
    end
  end

  # Wrapped with shell continuations so the comment stays readable and the
  # command stays runnable when a build carries a dozen flags.
  def generation_command_lines(width: 72)
    generation_command.each_with_object([]) do |word, lines|
      if lines.empty? || "#{lines.last} #{word}".length > width
        lines.last << " \\" unless lines.empty?
        lines << (lines.empty? ? +word : "  #{word}")
      else
        lines.last << " #{word}"
      end
    end
  end

  # A multi-line Ruby hash literal, punctuated here instead of in the template.
  #
  # Which entries a generated hash has depends on the flags, so a template that
  # writes its own commas is guessing which of its lines will end up last. In the
  # builds where it guesses wrong the literal trails a comma into its closing
  # brace (Style/TrailingCommaInHashLiteral), and where every entry happens to be
  # conditional it opens and closes over nothing at all. Hand over the entries
  # that actually exist and let this place the punctuation.
  #
  # +indent+ is the column the braces sit at; entries go two deeper. An entry may
  # be several lines (a comment above its pair), in which case the comma lands
  # after the last of them.
  def hash_literal(entries, indent:)
    return "{}" if entries.empty?

    pad  = " " * indent
    body = entries.map { |entry| entry.lines.map { |line| "#{pad}  #{line.chomp}" }.join("\n") }
    "{\n#{body.join(",\n")}\n#{pad}}"
  end

  # The attribute and param names install_parameter_filters redacts: the ones this
  # build introduces that Rails' stock list doesn't already reach. It reaches most
  # of them by substring — :passw covers password_digest, :otp and :secret cover
  # totp_secret, :token covers the emailed token, :email covers both the column and
  # pending_email — which is why none of those repeat here.
  def parameter_filters
    filters = []
    # The provider's identifier for the account. Not a credential, but a strategy
    # may put anything it likes in it, and several put the address or the handle
    # there (the developer strategy uses the email) — which quietly undoes the
    # redaction of the email column sitting one line above it in an `inspect`.
    filters << "uid" if omniauth?
    # The number itself. phone_verified_at stays readable: it's a timestamp, and
    # knowing when a number was proved is worth more in a log than it costs.
    filters << "phone" if phone?
    # An invitation address, under a column name :email can't see.
    filters << "sent_to" if invitable?
    # params[:code] on the way in: a recovery code, a texted one-time code, or an
    # OAuth authorization code on the callback. This also covers recovery codes
    # before they are digested.
    filters << "code" if second_factor? || sms? || omniauth?
    # The authenticator code answering a sudo bar. Its own entry because the filter
    # above is anchored (so unrelated names containing "code" stay readable), so it doesn't
    # reach a prefixed name. sudo_password needs no entry — Rails' stock list
    # matches "passw" as a substring.
    filters << "sudo_code" if sudoable? && sudo_bars.include?(:totp)
    # The bearer token every emailed link arrives under.
    filters << "sid" if email_verifiable? || recoverable? || magic_link?
    # The identifier typed at sign-in, and its copy in the bounce URL. `email_hint`
    # the stock :email already reaches, and a username is not a secret.
    filters.push("login", "login_hint") if multi_login?
    filters << "#{login_field}_hint" if !multi_login? && login_field.to_s == "phone"
    # The unproved number, under a column name /\Aphone\z/ can't see.
    filters << "pending_phone" if phone_verifiable?
    filters
  end

  # Anchored, rather than the bare symbols the stock list is written in. Those
  # match on substrings, and this list is the host app's: `uid` alone would also
  # swallow its `uuid` and `guid`, while `code` would hide unrelated names that
  # merely contain the same substring.
  def filter_regexp(name) = "/\\A#{name}\\z/"

  # ---- the destination app --------------------------------------------------

  def in_destination(relative_path) = File.join(destination_root, relative_path)

  # A concern with a generic name (Principals, Eventable) sits in app/models/concerns
  # for the default identity; a namespaced identity's copy joins its other models.
  def shared_concern_path(file) = "app/models/#{"concerns/" unless identity.namespaced?}#{file}.rb"

  def partial_file(name) = "app/views/#{File.dirname(name)}/_#{File.basename(name)}.html.erb"

  # A second identity asks for gems the first one already added.
  def gem(name, *, **)
    super unless File.read(in_destination("Gemfile")).match?(/^\s*gem "#{name}"/)
  end

  def bcrypt_present?
    File.read(in_destination("Gemfile")).include?('gem "bcrypt"')
  rescue Errno::ENOENT
    false
  end

  def importmaps?
    File.exist?("config/importmap.rb")
  end

  # Every condition #add_gems writes a gem under.
  def gem_dependencies?
    password? || second_factor? || pwned? || strong_passwords? || omniauth? ||
      webauthn_credentials? || principals.email || phone?
  end

  def filter_parameters_line(names)
    "Rails.application.config.filter_parameters += [ #{names.map { |name| filter_regexp(name) }.join(", ")} ]"
  end

  # ---------------------------------------------------------------------------
  # What this build is
  #
  # The identity and principal sets, and the flag predicates derived from them.
  # Everything here answers a question about the build, and the expressions a
  # template needs sit beside the predicate that decides whether to emit them.
  # ---------------------------------------------------------------------------

  # The identity being generated: derives the class name, table, sessions, route
  # and controller slugs, cookie, and path/account prefixes from --user-class
  # (default "User") and the scoping flags.
  def identity
    @identity ||= AuthnzEleven::Identity.new(
      class_name: options[:user_class],
      namespaced: options[:namespaced]
    )
  end

  # The identifying attributes (principals) and their roles for this run — which
  # columns exist, which are login keys, which can receive messages. With no
  # principal flags this set is empty; validate_principal! rejects that shape.
  def principals
    @principals ||= AuthnzEleven::Principals.from_options(options)
  end

  # The sign-in login key when the form posts a single field. A multi-login
  # build dispatches between several principals instead.
  def login_principal = principals.login_principals.first
  def login_field     = login_principal.column
  def multi_login?    = principals.multi_login?

  # A phone principal is present (--phone=required|optional). Gates the phonelib
  # gem, the phone column's validation, the registration/settings phone field, and
  # (3b) the SMS verification flow.
  def phone?          = !principals.phone.nil?

  # Whether the phone column is NULL-able. An optional phone obviously is; a
  # *required* one is too under --guestable, because guests carry a nil number (no
  # synthesized numbers — that would risk texting a real stranger), so presence is
  # enforced by the model validation's `unless: :guest?` rather than by NOT NULL.
  def phone_column_nullable?
    principals.phone&.then { |p| p.optional? || guestable? } || false
  end

  # The sign-in form's identifier field name. One login key → its own column
  # ("email"). Several → a single field-agnostic "login" the controller
  # dispatches by shape ("@" means email).
  def sign_in_field = multi_login? ? "login" : login_field

  # The redirect hint param that carries the just-entered identifier back to the
  # form. Single-key builds name the field ("email_hint"); multi-key builds use
  # the field-agnostic "login_hint".
  def login_hint_param = multi_login? ? "login_hint" : "#{login_field}_hint"

  # A no-password lookup by whichever login key was submitted, as a Ruby
  # expression for the templates. Single-key builds look the one column up
  # directly; multi-key builds fold the "@"-dispatch into the model's
  # find_by_login (generated only then, in Authenticatable).
  def find_by_login_expr(identifier_expr)
    if multi_login?
      "#{identity.class_name}.find_by_login(#{identifier_expr})"
    else
      "#{identity.class_name}.find_by(#{login_field}: #{identifier_expr})"
    end
  end

  # Copy for a failed sign-in lookup — names the login key(s), stays paranoid.
  # Punctuation is added by each caller (HTML ends the sentence with a period,
  # the JSON API omits it). A multi-key build names both keys ("username/email").
  def incorrect_login_message
    keys = multi_login? ? login_principals.map(&:column).join("/") : login_field
    "That #{keys} or password is incorrect"
  end

  # The two halves of the sign-in miss branch, which is now the only place a deadbolt
  # is spoken about: authenticate_with_password answers nil for a deadbolted account
  # exactly as it does for a wrong password, so a coy build has nothing to say and
  # nothing to decide.
  #
  # A --no-coy build is honest about account existence, so it keeps the record it
  # just looked up in order to tell a deadbolted visitor to come back later. The
  # window is real (config.deadbolt.duration), so "try again later" is true rather
  # than a brush-off, and it never says "deadbolted" — that is our word, not theirs.
  def failed_sign_in_lookup
    return deferred_call(identity.class_name, :register_failed_attempt, "#{login_identifier_expr}#{".to_s" unless multi_login?}") if coy?

    "other = #{identity.class_name}.register_failed_attempt(#{login_identifier_expr})"
  end

  # Work that happens only for some accounts leaves the request in a coy build, so
  # response timing can't tell which accounts exist.
  def deferred_call(receiver, method, *args)
    return "AuthnzElevenDeferredJob.perform_later(#{[receiver, ":#{method}", *args].join(", ")})" if coy?

    "#{receiver}.#{method}#{"(#{args.join(", ")})" if args.any?}"
  end

  # +period+ follows incorrect_login_message's rule: HTML ends the sentence, the
  # JSON API doesn't.
  def failed_sign_in_alert(period: true)
    stop = "." if period
    return %("#{incorrect_login_message}#{stop}") if coy?

    %(other&.deadbolted? ? "Too many failed attempts. Please try again later#{stop}" : "#{incorrect_login_message}#{stop}")
  end

  # The expression each sign-in shape holds its submitted login key in.
  def login_identifier_expr = multi_login? ? "identifier" : "params[:#{login_field}]"

  def login_principals = principals.login_principals

  # Whether a record can be saved with every login key blank — which is an account
  # nobody can ever sign in to again. It saves cleanly and even signs in once, and
  # is only discovered later at a sign-in form with nothing to type into it.
  #
  # No single presence rule can prevent it: each key is legitimately optional on its
  # own, and what must hold is that *some* one of them is filled. So the models get
  # a record-level check instead (the Principals concern's #at_least_one_login_key),
  # and only where it can fire — a build with any required login key already has its
  # guarantee, and a second rule there would be dead code.
  #
  # validate_email_none! is the same question one step earlier: it refuses a build
  # whose email COLUMN is missing with nothing to replace it, this catches the row
  # whose optional columns all came back blank.
  def login_key_may_be_missing? = login_principals.all?(&:optional?)

  # Whether every account must hold a channel (--contactable, on by default).
  def contactable? = options.contactable?

  # Whether that promise needs a record-level rule, or is already guaranteed.
  #
  # Emitted only where it can fire, so it is never dead code restating a rule
  # something else already enforces. Four ways it can't fire:
  #
  #   * --no-contactable: no promise to keep
  #   * fewer than two channels: validate_contactable! has already refused the
  #     ambiguous shape, so a lone channel here is required and says so itself
  #   * a required channel: its own presence rule IS the guarantee
  #   * every login key is a channel: at_least_one_login_key already emits this
  #     exact condition, character for character
  #
  # What's left is a non-channel login key (a username) beside two optional
  # channels — the account can sign in holding neither, and nothing else notices.
  def contactable_validation?
    return false unless contactable?

    channels = principals.select(&:channel?)
    channels.size > 1 && channels.none?(&:required?) && !login_principals.all?(&:channel?)
  end

  # "They submitted no channel at all", as a Ruby condition. Only asked in builds
  # where that is possible AND survivable, so the branch it guards is never dead.
  def channels_blank_condition
    principals.select(&:channel?).map { |principal| "@registration.#{principal.column}.blank?" }.join(" && ")
  end

  # Natural-language list of the login keys for user-facing copy ("username, email,
  # or phone"). A single-key build reads as just the column ("email").
  def login_keys_phrase = or_phrase(login_principals.map(&:column))

  # "a", "a or b", "a, b or c". Three callers below want this and none of them
  # want it to disagree with the others.
  def or_phrase(items)
    return items.first if items.one?

    "#{items[0..-2].join(", ")} or #{items.last}"
  end

  # The same list with articles, for a sentence addressed to somebody filling in a
  # form ("Enter an email or a phone number."). login_keys_phrase reads as a label;
  # this reads as an instruction.
  ARTICLED_PRINCIPAL_NOUNS = {
    email: "an email address", phone: "a phone number", username: "a username"
  }.freeze

  def login_keys_article_phrase
    or_phrase(login_principals.map { |principal| ARTICLED_PRINCIPAL_NOUNS.fetch(principal.type) })
  end

  # The same, for the channels — what must_be_contactable tells somebody to add.
  def channel_keys_article_phrase
    or_phrase(principals.select(&:channel?).map { |principal| ARTICLED_PRINCIPAL_NOUNS.fetch(principal.type) })
  end

  # The argument list for a sign-up's params.permit — the principal columns this
  # form may submit, plus whatever else the call site needs, as one "permit"
  # fragment (e.g. ":email, :password, :password_confirmation").
  #
  # A single-channel invite-only build pins that channel to the invitation
  # (merged server-side by #user_params / #registration_params, never permitted).
  # A multi-channel build permits both and lets the final merge replace only the
  # addressed one. A username is still collected from the form.
  #
  # The extras are arguments rather than something a call site concatenates,
  # because the principal list can be *empty*: an invite-only build whose only
  # principal was the address has nothing left to permit. Joining here is what
  # renders that as `params.permit(:password, :password_confirmation)`, or a bare
  # `params.permit()`, rather than a stray leading comma.
  def permit_list(*extra)
    cols = principals.map(&:column)
    cols -= [principals.channels.first.column] if invitation_pins_only_channel?
    (cols + extra.map(&:to_s)).map { |c| ":#{c}" }.join(", ")
  end

  # The whole right-hand side of a sign-up's params method, so the emitted method
  # is one line whether or not there's an invitation to pin the address to.
  def sign_up_params_expression
    extra = password_on_sign_up_form? ? %w[password password_confirmation] : []
    permitted = "params.permit(#{permit_list(*extra)})"
    invitable? ? "with_invitation(#{permitted})" : permitted
  end

  # The whole pair, not just the key: a dynamic key needs a hash rocket, a
  # literal one must not have it (Style/HashSyntax).
  def invitation_channel_pair
    return "invitation.sent_to_channel => invitation.sent_to" if multi_channel_invitable?

    "#{principals.channels.first.column}: invitation.sent_to"
  end

  # An app with none of these leaves a locked-out user no way back in. Used only
  # to warn at install time; enforcing nothing (it's a legitimate choice).
  # recoverable? implies password?, so this can't advertise a password
  # reset for an app that has no password. --sms-code counts: someone who forgot
  # their password can still get in with a texted code.
  def recovery_path? = recoverable? || magic_link? || omniauth? || sms_code?

  # A legal typed submission needs pre-account enrollment unless the form itself
  # guarantees a password or a required channel becomes a usable configured door.
  # This is deliberately a build capability; PendingRegistration#next_step answers
  # the corresponding question for one row.
  def typed_registration_guarantees_sign_in_method?
    password_required? ||
      (magic_link? && principals.email&.required?) ||
      (sms_code? && principals.phone&.required?)
  end

  def credential_staged_registration?
    typed_registration? && !typed_registration_guarantees_sign_in_method?
  end

  def pre_account_password_enrollment? = credential_staged_registration? && password?
  def pre_account_passkey_enrollment? = credential_staged_registration? && passkey?

  # What the gate offers, which is not the same as what could clear it.
  #
  # A provider is deliberately absent. A provider sign-up arrives already holding
  # :omniauth and is never staged, so everybody here took the typed route and
  # declined the button on the sign-up form. Offering it back asks a question they
  # answered on the previous page. It returns below as the fallback for the build
  # where it is the only way out.
  def registration_credential_options
    [(:password if pre_account_password_enrollment?),
     (:passkey if pre_account_passkey_enrollment?)].compact
  end

  # The build with nothing else to enroll. Here the provider button is not a
  # question already answered, it is the only door this sign-up can reach.
  def pre_account_provider_enrollment?
    credential_staged_registration? && omniauth? && registration_credential_options.empty?
  end

  # Whether an invitation addressed to this channel becomes an account at the
  # sign-up POST. The invitation proves its own channel, but a second channel the
  # build requires is still unproved and holds the registration open — as does a
  # build whose form leaves the row with no way to sign in.
  def email_invitation_completes_registration? = invited_registration_completes?(:email)
  def phone_invitation_completes_registration? = invited_registration_completes?(:phone)

  def invited_registration_completes?(channel)
    return true unless typed_staged_registration?
    return false unless typed_registration_guarantees_sign_in_method? || channel_door?(channel)

    other = principals.select(&:channel?).find { |principal| principal.type != channel }
    !(other&.required? && channel_verifiable?(other))
  end

  def channel_door?(channel) = channel == :email ? magic_link? : sms_code?

  # The emitted sign-up fixture fills every channel, so once they are proven any
  # channel-backed door signs it in, whatever the build guarantees.
  def sign_up_fixture_can_sign_in? = password_required? || magic_link? || sms_code?

  # An invite-only sign-up needs an accepted invitation in the session before it posts.
  def accept_test_invitation(sent_to)
    path = identity.nested_helper("accept_invitation_path")
    [
      %(invitation = #{identity.invitation_class}.create!(sent_to: #{sent_to}, inviter: #{identity.plural}(:alice))),
      %(get #{path}(token: invitation.generate_token_for(:invitation)))
    ].join("\n    ")
  end

  # An invite-only staged row belongs to its invitation, so a test that builds one
  # outside the sign-up flow has to supply one too. `save(validate: false)` skips
  # the association's presence rule but not the column's NOT NULL.
  def staged_registration_invitation(address)
    return "" unless invite_only?

    channel = (%(, sent_to_channel: "email") if multi_channel_invitable?)
    %(, invitation: #{identity.invitation_class}.create!(sent_to: #{address}#{channel}, inviter: @user))
  end

  # One step of the staged sign-up, wherever it is reached from. Emitted once, into
  # the Registering concern every registration controller includes.
  def advance_body
    lines = ["  def advance(registration)", "    case registration.next_step"]
    if omniauth_registration?
      lines << "    when :complete_profile"
      lines << "      redirect_to new_#{identity.route_scope}_omniauth_registration_path"
    end
    if email_gated_registration?
      lines << "    when :verify_email"
      lines << "      #{deferred_call("registration", :request_email_verification)}"
      lines << "      redirect_to #{identity.route_scope}_new_verify_email_path"
    end
    if phone_gated_registration?
      lines << "    when :verify_phone"
      lines << "      #{deferred_call("registration", :request_phone_verification)}"
      lines << "      redirect_to #{identity.route_scope}_verify_phone_path"
    end
    if credential_staged_registration?
      lines << "    when :enroll_credential"
      lines << %(      redirect_to #{credential_enrollment_path}, notice: "#{credential_enrollment_alert}")
    end
    lines += ["    when :complete", "      finish_registration(registration.complete)", "    end", "  end"]
    lines.join("\n")
  end

  # Only worth a page of its own when there is an actual choice to put on it. One
  # option means one destination, and a chooser above a single button is worse
  # than the button. The provider fallback needs the page too: a button is all it
  # has, and there is nowhere else to put one.
  def registration_credential_chooser? = registration_credential_options.size > 1
  def registration_credential_page? = registration_credential_chooser? || pre_account_provider_enrollment?

  def credential_enrollment_page_path(option)
    case option
    when :password then "#{identity.route_scope}_new_registration_password_path"
    when :passkey then "#{identity.route_scope}_new_registration_passkey_path"
    end
  end

  def credential_enrollment_path
    return "#{identity.route_scope}_finish_setup_path" if registration_credential_page?

    credential_enrollment_page_path(registration_credential_options.first) ||
      "#{identity.route_scope}_sign_up_path"
  end

  def credential_enrollment_alert
    return "Choose how you'll sign in to finish setting up your account." if registration_credential_chooser?

    case registration_credential_options.first
    when :passkey then "Create a passkey to finish setting up your account."
    when :password then "Choose a password to finish setting up your account."
    else "Connect an account to finish setting up your account."
    end
  end

  # The before_actions that hold a signed-in account at a page until it fixes
  # something, in the order they run: the callback, the predicate that lifts it,
  # the page it holds you at, and what it says there.
  def impediments
    [
      [admin_mfa_gate?, "require_admin_mfa", "admin_mfa_enrolled?", admin_mfa_hold_path,
       "#{totp? ? "Set up a second factor" : "Enroll a security key"} to continue."],
      [max_sessions_prompt?, "require_session_within_limit", "within_session_limit?",
       "#{identity.settings_helper_prefix}_sessions_path", "Sign out of another session to continue."],
      [password_rotatable?, "require_fresh_password", "password_fresh?",
       "edit_#{identity.settings_helper_prefix}_password_path", "Your password has expired. Choose a new one to continue."],
      [teams?, "require_team", "on_a_team?", identity.nested_helper("teams_path"), "Create or join a team to continue."]
    ].select(&:first).map { |_in_this_build, *impediment| impediment }
  end

  def impeded? = impediments.any?

  def impediment_callbacks = impediments.map { |callback, *| ":#{callback}" }.join(", ")

  def impediment_conditions = impersonatable? ? "if: :authenticated?, unless: :impersonating?" : "if: :authenticated?"

  def pending_registration_session_key = "pending_#{identity.singular}_registration"

  def interrupted_destination_key = session_key(:interrupted_destination)

  # Every identity writes into the one Rails session, so a namespaced identity's keys
  # carry its name or two identities would read each other's.
  def session_key(name) = identity.namespaced? ? "#{identity.singular}_#{name}" : name.to_s

  # Which second factors an account may enroll, from --second-factor=totp,webauthn.
  # Empty when the flag is absent, so second_factor? is "this build has any".
  def second_factors
    @second_factors ||= options.second_factor.to_s.split(",").map(&:strip).reject(&:empty?).map(&:to_sym)
  end

  def second_factor?    = second_factors.any?
  def totp?             = second_factors.include?(:totp)
  def security_keys?    = second_factors.include?(:webauthn)
  def sms_second_factor? = second_factors.include?(:sms)

  # More than one enrolled means a sign-in has to choose where to land, and each
  # challenge page has somewhere to link. Neither question exists with one factor,
  # so the chooser and the cross-links are generated only here.
  def multiple_second_factors? = second_factors.size > 1

  # The narrower pair: emitted tests that drive an authenticator and a security key
  # against each other need both to exist.
  def both_second_factors? = totp? && security_keys?

  # How an account is asked whether it holds each factor, strongest first — the
  # order the challenge chooser and second_factor_enrolled? both read.
  def second_factor_enrolled_clauses
    clauses = []
    clauses << "#{second_factor_keys_expr}.any?" if security_keys?
    clauses << "totp_enrolled_at?" if totp?
    clauses << "sms_enrolled_at?" if sms_second_factor?
    clauses
  end

  def second_factor_challenge_path_for(factor) = "new_#{identity.route_scope}_mfa_challenge_#{factor}_path"

  # The challenge chooser's body. The strongest factor the account actually holds
  # wins; the weakest is the fallthrough, so the chain always lands somewhere. With
  # one factor this is that factor's path and nothing else, which is what
  # start_new_session_for redirects to directly.
  def second_factor_challenge_lines
    branches = []
    branches << ["#{second_factor_keys_expr("user")}.any?", "security_keys"] if security_keys?
    branches << ["user.totp_enrolled_at?", "totp"] if totp?
    branches << ["user.sms_enrolled_at?", "sms"] if sms_second_factor?

    *guarded, (_, fallthrough) = branches
    guarded.map { |clause, factor| "return #{second_factor_challenge_path_for(factor)} if #{clause}" } <<
      second_factor_challenge_path_for(fallthrough)
  end

  # The "use something else instead" links a challenge page offers: every other
  # factor this build has, each shown only when the account actually holds it.
  # Empty with one factor, which is how the links disappear from those builds.
  def second_factor_alternatives(except)
    factors = []
    factors << ["security_keys", "#{second_factor_keys_expr("@user")}.any?", "Use a security key instead"] if security_keys?
    factors << ["totp", "@user.totp_enrolled_at?", "Use your authenticator app instead"] if totp?
    factors << ["sms", "@user.sms_enrolled_at?", "Get a code by text instead"] if sms_second_factor?

    factors.reject { |factor, _, _| factor == except.to_s }
           .map { |factor, clause, label| [clause, label, second_factor_challenge_path_for(factor)] }
  end

  # --second-factor=webauthn is security keys as a *second* factor; --passkey is
  # passkeys as a *primary* passwordless door (a strategy of its own, no second
  # factor). Both are WebAuthn credentials stored in the same table, so
  # webauthn_credentials? gates the shared machinery (gem, RP initializer,
  # webauthn_credentials table + model, webauthn_handle, the JS controller).
  def passkey? = options.passkey?
  def webauthn_credentials? = security_keys? || passkey?

  # Only when a build has both roles does the shared table need to tell them
  # apart (so the two management UIs don't list each other's credentials); the
  # authentication_factor column and the model scopes exist only in that case.
  def passkey_and_security_keys? = passkey? && security_keys?

  # How the templates ask for an account's second-factor keys: plain in a build
  # where every credential is one, scoped where passkeys share the table. Pass no
  # receiver inside the model itself.
  def second_factor_keys_expr(receiver = nil)
    "#{receiver}#{"." if receiver}webauthn_credentials#{".second_factors" if passkey_and_security_keys?}"
  end

  # The role a credential is created with, where the build has both.
  def factor_attr(role) = (", authentication_factor: :#{role}" if passkey_and_security_keys?)

  # The sign-in doors a user's enrolled second factor is required at by default:
  # every knowledge/possession door this build actually has. A passkey door
  # (when it exists) is deliberately omitted — a passkey is itself a strong,
  # phishing-resistant factor, so it clears the bar on its own and is never
  # stepped up. Seeds config.second_factor.needed_after, which the app owner can
  # edit. Provider doors are never seeded: a provider names itself (:google, not
  # :omniauth) and only the app knows which ones it has configured.
  def default_needed_after
    strategies = []
    strategies << :password if password?
    strategies << :sms_code if sms_code?
    strategies
  end

  # ---- sessions -------------------------------------------------------------

  # Emit a sign-in call. Every one names the door it came through, so
  # config.second_factor.needed_after describes the whole policy and no site can
  # sidestep it, and sessions.via records it.
  # +subject+ is the local holding the user ("user", "@user"). +via+ is a Symbol
  # for a fixed door, or a String of Ruby for one only the request knows (the
  # omniauth provider).
  #
  # With two-factor the call can divert to the MFA challenge and answer false, so
  # a door must `return unless` it. Pass may_challenge: false where that can't
  # happen — an account created moments ago has no factor to be asked for — and
  # the guard is left off rather than emitted dead.
  def sign_in_call(subject, via:, remember_expr: nil, may_challenge: true)
    remember = ", remember: #{remember_expr}" if rememberable? && remember_expr
    door = via.is_a?(Symbol) ? ":#{via}" : via
    call = "start_new_session_for(#{subject}, via: #{door}#{remember})"
    may_challenge && second_factor? ? "return unless #{call}" : call
  end

  def trackable?              = options.trackable?
  def last_seenable?          = options.last_seenable?
  def security_notifications? = options.security_notifications?
  def api_tokens? = options.api_tokens?

  # "Remember me" is a cookie-lifetime policy on the browser session cookie, and
  # the idle timeout resolves the DB session per request.
  def rememberable?  = options.rememberable?
  def timeoutable?   = options.timeoutable?

  # A concurrent-session cap enforced at the one choke point every door funnels
  # through (start_new_session_for).
  def max_sessionable? = options.max_sessionable.present?

  # Which over-limit strategy the flag selected. "evict" (default) silently signs
  # out the least-recently-active session at sign-in; "prompt" holds the new
  # sign-in at a completion gate until the user trims a session themselves.
  def max_sessions_evict?  = max_sessionable? && options.max_sessionable == "evict"
  def max_sessions_prompt? = max_sessionable? && options.max_sessionable == "prompt"

  # Whether this build has a typed sign-up FORM — not whether accounts can be
  # created. The omniauth callback registers with no form at all, which is why
  # pending_registration? asks that separately.
  def typed_registration? = options[:registration] != "closed" && !social_login_only?

  # Whether to advertise a *public* sign-up path in the UI. Invite-only keeps the
  # registration controller and route (reached only via an invitation link), but
  # there is no open sign-up — so the login page must not link to one.
  def public_registration? = typed_registration? && !invite_only?

  # has_secure_password is opt-in. Any feature that is meaningless without a
  # password implies it — you can't reset or breach-check a password that doesn't
  # exist — so asking for one turns --password on (same shape as adminable? below).
  # Two flags are deliberately NOT here. sudoable? re-proves whatever factor the
  # user actually holds, so it never assumes a password exists. deadboltable?
  # needs one, but asking for a brute-force defence is not asking for the thing
  # being defended — validate_deadboltable! refuses that rather than invent a door.
  def password? = options.password? || recoverable? || pwned? || strong_passwords? || password_rotatable? || password_historical?

  # Password reset ("forgot password"). Opt-in, and implies --password
  # (see above). Orthogonal to --magic-link: reset recovers a *passworded*
  # account, while magic-link is an additive way in that needs no password.
  def recoverable? = options.recoverable?

  # Password expiry / rotation. Opt-in, implies --password (you can't
  # expire a password that doesn't exist). The maximum age itself lives in the
  # initializer (config.password.maximum_age, default 90.days; nil disables),
  # tunable without regenerating — the same config-not-flag shape as
  # timeoutable?'s idle_timeout and the session cap.
  def password_rotatable? = options.password_rotatable?

  # Password-reuse history. Opt-in, implies --password. The depth lives in the
  # initializer (config.password.history_depth, default 5; nil keeps archiving
  # but stops rejecting).
  def password_historical? = options.password_historical?

  # Whether a channel gets proved, asked one channel at a time. --no-verifiable is
  # a single opt-out that drops verification everywhere, but these predicates stay
  # per-channel so every template asks "does *this* channel verify?" rather than "is
  # the flag set?" — which is what would let a per-channel opt-out arrive without
  # touching a template.
  #
  # Each is keyed to its own principal, so a build without that principal forces it
  # false and emits none of its flow.
  #
  # Email: a signed link, clicked from the inbox. Dropping it takes the staged sign-up
  # and staged change, their tokens, mailers, controllers, routes and views; sign-up
  # then creates the account straight away and settings writes the column directly.
  def email_verifiable? = options.verifiable? && !principals.email.nil?

  # Phone: a six-digit one-time code, typed into a form. Dropping it takes the staged
  # sign-up and staged change and their controllers, routes and views, leaving the
  # plain phone column and its login-key dispatch untouched. It is also what pulls in
  # the whole SMS delivery seam (see sms?), so a build that wants a phone column
  # without an SMS vendor is the case --no-verifiable serves.
  def phone_verifiable? = options.verifiable? && !principals.phone.nil?

  def channel_verifiable?(principal) = principal.type == :email ? email_verifiable? : phone_verifiable?

  # --encrypted-pii is a single boolean because invitations.sent_to holds either
  # channel in one column, so a per-channel split has no coherent answer there. The
  # predicates stay per-channel anyway, so every template asks about a channel rather
  # than about the flag.
  def email_encrypted? = options.encrypted_pii? && !principals.email.nil?
  def phone_encrypted? = options.encrypted_pii? && !principals.phone.nil?

  # A TOTP secret is the one reversible credential in the schema — it can't be digested,
  # because verifying a code means recomputing it. So it is always encrypted, with no
  # flag: plaintext there means a database dump is a set of working second factors.
  # Nothing queries it, so it takes the random-IV mode and rotates freely.
  def encryption? = encrypted_pii? || totp?

  def encrypted_pii? = options.encrypted_pii?

  # Whether this build generates a way for the account holder to change the value
  # themselves: the /settings resource, its form, and — where the channel is
  # verified — the whole staged-change apparatus behind it (the pending_ column,
  # its token and mailer, the confirm and resend endpoints). ",permanent" is the
  # flag that turns these off.
  def email_changeable? = !principals.email.nil? && principals.email.changeable?
  def phone_changeable? = !principals.phone.nil? && principals.phone.changeable?

  # A staged change, proved before it lands. Distinct from email_gated_registration?,
  # which proves the value an account is BORN with — a permanent build keeps that and
  # drops this.
  def email_change_verification? = email_verifiable? && email_changeable?
  def phone_change_verification? = phone_verifiable? && phone_changeable?

  # Cache-backed six-digit challenges. A signed-link phone invitation needs the
  # provider and delivery job but none of this code-entry machinery.
  def sms? = phone_verifiable? || sms_code? || sms_second_factor?

  # The app-global SMS provider seam, generated for challenges or invitations.
  def sms_delivery? = sms? || phone_invitable?

  # Proof staging and method staging are independent capabilities. A provider
  # sign-up that still owes profile fields is the third reason the aggregate exists.
  def channel_staged_registration?
    typed_registration? && (email_verifiable? || phone_verifiable?)
  end

  # Whether the typed sign-up form stages a row rather than creating the account.
  def typed_staged_registration? = typed_registration? && (channel_staged_registration? || credential_staged_registration?)

  def pending_registration_model? = typed_staged_registration? || omniauth_registration?

  # Where the row carries a provider login: either the provider sign-up itself, or
  # a typed sign-up whose only credential is connecting one.
  def pending_registration_holds_provider? = omniauth_registration? || pre_account_provider_enrollment?

  # Compatibility for older, non-emission helpers while callers migrate to the
  # capability they actually need.
  alias pending_registration? pending_registration_model?

  # What the sign-up form renders errors and values from. A staged build is filling
  # in a PendingRegistration, not a half-built account, and the view should say so.
  def registration_form_object = typed_staged_registration? ? "@registration" : "@user"

  # Whether a sign-up can arrive with no channel to prove at all. Such a request has
  # nothing to wait for and nothing to hide, so it becomes an account immediately.
  #
  # Requires --no-contactable: with the default on, an account holding no channel is
  # refused either by must_be_contactable or by the column's own presence rule, so
  # this branch and everything it guards would be unreachable. Keyed to the flag
  # rather than to "every channel happens to be optional", so a build only has this
  # shape when it asked for it.
  def channel_less_registration?
    !contactable? && pending_registration_model? &&
      principals.select(&:channel?).all?(&:optional?) && !login_key_may_be_missing?
  end

  # What a staged sign-up carries over to the account besides the channel that
  # just proved it: every principal that needs no proof, plus the password when
  # there is one.
  def staged_attributes_entries
    entries = principals.reject(&:channel?).map { |principal| "#{principal.column}: #{principal.column}" }
    entries << "password_digest: password_digest" if password_on_sign_up_form?
    entries
  end

  # Empty in a build whose only principals are channels and whose door needs no
  # password — a magic-link-only sign-up carries nothing across. There the method
  # and its splat are both skipped rather than emitted as a `{}` nobody reads.
  def staged_attributes? = staged_attributes_entries.any?

  def staged_attributes_literal(indent:) = hash_literal(staged_attributes_entries, indent: indent)

  # How the carried values ride into a create! whose channel columns are already
  # spelled out literally. A trailing splat, or nothing at all.
  def staged_attributes_splat = (", **staged_attributes" if staged_attributes?)

  # The channels a staged row can mint an account from. A deferred phone is absent
  # on purpose: it mints nothing, it is parked on an account the email already minted.
  def minting_channel_columns
    columns = []
    columns << principals.email.column if email_verifiable?
    columns << principals.phone.column if phone_registration_claim?
    columns
  end

  # Whether PendingRegistration has a private section to open at all. A build whose
  # sign-up carries nothing, defers nothing and claims no username has every one of
  # its methods public, and a bare `private` before `end` would be the only thing
  # under it.
  def pending_registration_privates?
    staged_attributes? || omniauth? || !principals.username.nil?
  end

  # Passwordless sign-in by texted code — a door, the phone sibling of --magic-link.
  # The phone principal is explicit; validate_sms_code_option! requires it.
  def sms_code? = options.sms_code?

  # Whether an emailed link is the gate a staged sign-up hands off to — the sibling
  # of phone_gated_registration?. It decides everything that link touches: the
  # mailer method and its view, the token purpose and its expiry key, the "check
  # your email" page, and the controller that redeems it.
  #
  # Distinct from email_verifiable?, which only says there is an address worth
  # proving; an account can be asked to prove one long after sign-up.
  def email_gated_registration?
    email_verifiable? && typed_staged_registration? && typed_sign_up_may_owe?(principals.email)
  end

  # An invite-only sign-up arrives with the invited channel proved and drops an optional
  # other one, so it can only owe a required channel the invitation might not have used.
  def typed_sign_up_may_owe?(principal)
    !invite_only? || (principal.required? && multi_channel_invitable?)
  end

  # The sign-up form never collects the channel: it is the invitation's address.
  def invitation_pins_only_channel? = invite_only? && !multi_channel_invitable?

  # Where to send someone whose staged sign-up is gone. The sign-up form, when this
  # build has one — an omniauth-only build stages from the callback and has no form
  # to go back to, so it offers the sign-in page and its provider buttons instead.
  def registration_entry_path
    return "#{identity.route_scope}_sign_up_path" if typed_registration?

    "#{identity.route_scope}_sign_in_path"
  end

  # Whether an SMS code is the gate a typed sign-up must clear — the phone sibling
  # of email_gated_registration?.
  def typed_phone_gated_registration?
    phone_verifiable? && typed_staged_registration? && typed_sign_up_may_owe?(principals.phone)
  end

  # Either sign-up proves its number this way: the typed form, or a provider's profile form.
  def phone_gated_registration? = typed_phone_gated_registration? || omniauth_registration_verifies_phone?

  # Non-disclosure of whether an account exists — Devise calls this "paranoid";
  # named --coy here instead, since that's closer to what it actually does (evasive,
  # not fearful). Off by default, for the better user experience; with --coy every
  # channel-principal flow that could confirm an address (password reset,
  # magic-link request, email change, the locked-account message) gives the same
  # response whether or not the address is on file. Responses only: the coy
  # branches still differ in timing. This is a *generation-time* choice, not a runtime
  # config, so the unchosen branch never ships to the app. Public principals
  # (username) are honest regardless (Principal#publicly_unique?), and
  # --no-verifiable independently forces honest *sign-up*, since the "check your
  # email" step was what covered the coy answer.
  def coy? = options.coy?
  def magic_link? = options.magic_link?
  # Teams are absent unless --teams is present. Each mode sets Current.team its own
  # way — the route, the middleware, or the session — and team_members_only then
  # checks membership without knowing which.
  def teams?                = options[:teams].present?
  def scope_teams?          = options[:teams] == "scope"
  def middleware_teams?     = options[:teams] == "middleware"
  def session_carries_team? = options[:teams] == "session"

  def team_root_helper = identity.nested_helper("team_root_path")

  def team_foreign_key = identity.namespaced? ? "{ to_table: :#{identity.teams_table} }" : "true"

  # A page an emitted test can visit that runs the team gate. Every generated page
  # is a remedy that skips it, so this is the team's own page or the host's root,
  # and a namespaced identity keeping its team in the session has neither.
  def team_gated_page
    return "#{team_root_helper}(team_id: #{identity.teams_table}(:acme))" if scope_teams?

    "root_path" unless identity.namespaced?
  end

  def admin_module = identity.nested_module("Admin")
  def admin_controller = identity.nested_module("AdminController")
  def admin_helper(name) = identity.nested_helper("admin_#{name}")

  def team_id_constraint = primary_key_type == "uuid" ? '/\h{8}-\h{4}-\h{4}-\h{4}-\h{12}/' : '/\d+/'
  # Development-only "sign in as anyone" shortcut. What it *includes* depends on
  # the primary auth strategy: with a password it's the sign-in-form bypass
  # (the EasyDevLogin concern); passwordless it's an explicit dev-only email
  # field + endpoint (there's no credential form to piggyback). Both share the
  # "type an email, become that user" gesture.
  def easy_dev_login? = options.easy_dev_login?
  def pwned? = options.pwned?
  # Password strength scoring is a second, orthogonal password-quality validation
  # (see --pwned): both are `validates :password` lines, and either one implies
  # --password since there's no password to score without it.
  def strong_passwords? = options.strong_passwords?
  # A human/anti-abuse challenge on the *unauthenticated* write forms. It's a
  # property of the request (verified in a controller concern), not of the User
  # record — so unlike --pwned/--strong-passwords it never touches the model. Turnstile is
  # the shipped provider; Captcha.provider in app/lib/captcha.rb is the seam for others.
  def captchable? = options.captchable?

  # The widget does not survive a Turbo body swap, and these forms re-render on failure.
  def captcha_form_options = captchable? ? ", data: {turbo: false}" : ""

  # Re-prove before sensitive actions. Bar-aware: it clears the user's strongest
  # available factor, so (unlike before) it does NOT imply --password.
  def sudoable?      = options.sudoable?

  # The user a sudo re-prove must clear: always the signed-in admin, never the
  # person they're impersonating.
  def sudo_subject = "#{identity.current_class}.#{impersonatable? ? "true_user" : "user"}"

  # The sudo bars this build can pose, in the order Sudoable#sudo_strategy tries
  # them. Ordered by what the person can actually produce at the keyboard right
  # now, not by cryptographic strength:
  #
  #   :webauthn  one touch, phishing-resistant, and on the device they're holding.
  #   :password  no second device involved, so it is the one bar that is always
  #              available to whoever has one.
  #   :totp      last, because ranking it above the password would trap anyone who
  #              signed in with a recovery code after losing the phone.
  #
  # :password is terminal when every user in the build has one, which is why :totp
  # drops out entirely unless --omniauth can produce a passwordless account. That
  # is also what keeps the emitted method free of unreachable branches.
  def sudo_bars
    bars = []
    bars << :webauthn if webauthn_credentials?
    bars << :password if password?
    bars << :totp     if totp? && !unconditional_password_bar?
    bars
  end

  # Whether an account that can reach a sudo bar might hold no password. Guests are
  # not in scope: they are never authenticated, so they never reach one, and their
  # NULL digest doesn't make the bar conditional for anyone who does — which is why
  # this is password_nullable? minus that clause rather than the same question.
  def passwordless_account_possible?
    !password? || password_form_optional? || password_deferred? || omniauth?
  end

  # Every account in this build has a password it chose, so the password bar always
  # applies and nothing after it can be reached.
  def unconditional_password_bar? = password? && !passwordless_account_possible?

  # One bar, and every account has it — so which bar to pose is known at generation
  # time. sudo_strategy would be a method returning a constant, every dispatch on it
  # a branch with one arm, and the helper_method that exposes it to the challenge
  # partial pure ceremony. All of it is emitted away.
  #
  # A passkey-only or authenticator-only build does NOT qualify: both fall through to
  # :open for an account that hasn't enrolled, so the branch is load-bearing there.
  def single_sudo_bar? = sudo_bars == [:password] && unconditional_password_bar?

  # Sudo can hit the "no re-provable factor" case (a user whose only credential is
  # omniauth or a magic link) only when the build can produce such a user. There we
  # fail open rather than lock them out of the guarded action. Same question as the
  # password bar's, from the other side.
  def fail_open_sudo? = sudoable? && passwordless_account_possible?

  # ---- credentials an account may remove ------------------------------------

  # Credentials an account may hold and remove: several passkeys or provider
  # logins, or — where password_removable? below is true — the password itself. Their
  # settings pages carry a refusal rather than a sudo bar: a bar you can clear is
  # the wrong answer to an action nobody should be able to take, because the thing
  # being prevented is not impersonation but lockout, and proving who you are does
  # not make locking yourself out safe.
  #
  # Whether a removal would in fact lock the account is a question about the
  # ACCOUNT, and this predicate only says which builds need to ask it. The answer
  # itself is the model's #last_sign_in_method?, which can see the row. Deciding it
  # per door at generation time cannot: a build with two of them would guard
  # neither, and a provider-registered user could unlink into an account they can
  # no longer reach.
  def removable_credentials? = passkey? || omniauth? || password_removable?

  # Doors that identify an account by something other than a password. Their
  # presence is what lets --password=optional be offered at all: an account can
  # decline a password and still have a way in.
  def non_password_doors? = passkey? || omniauth? || magic_link? || sms_code?

  # What the SIGN-UP FORM does about a password — not what every account holds.
  # Nothing typed into a form can speak for an account minted somewhere else, so
  # password_nullable? below asks its own question.
  #
  # "optional" carries the sense --contactable gave --email=optional: optional
  # BECAUSE another door covers you, not "may be absent". WHICH door covers a
  # given account is a per-row fact. PendingRegistration answers it before account
  # creation; #last_sign_in_method?(:password) answers it later at removal time.
  def password_form_optional? = password? && options[:password] == "optional"
  def password_required? = password_on_sign_up_form? && !password_form_optional?

  # Whether the password is enrolled after proof rather than typed on the initial
  # form. The unfinished attempt remains a PendingRegistration until the password
  # and account can commit together.
  #
  # The only credential here with a choice about when. A passkey is always enrolled
  # afterwards, a provider ceremony IS the arrival, and a magic link or SMS code is
  # not enrolled at all — a verified channel is already the door.
  def password_deferred? = password? && options[:password] == "deferred"

  # Whether the sign-up form carries a password field at all. Sites that care about
  # the FORM ask this; sites that care about the BUILD ask #password?.
  def password_on_sign_up_form? = password? && !password_deferred?

  # Whether any path in this build can mint an account with no password on file.
  # Decides the column's nullability, whether the presence rule can be lifted from
  # a row, and whether settings needs a way to SET a first password.
  #
  # Three paths can: a form that lets the field be blank, the OmniAuth callback (a
  # provider hands back no password and never will), and guest creation. The other
  # doors cannot — a --password --passkey build still collects a password from
  # everyone who signs up, and the passkey is an addition to it.
  #
  # Which ROWS may lack one, not which builds have another door. Where this is true
  # the excused rows hold a real NULL rather than a synthesized password nobody
  # can type.
  def password_nullable? = password? && (password_form_optional? || password_deferred? || omniauth? || guestable?)

  # Whether settings offers to REMOVE a password. Only where the form called it
  # optional on the way in: a build that insists on one at sign-up does not then
  # offer a door out of it. An account minted without a password can still SET
  # one wherever password_nullable? holds — that is the add half, and it is not
  # this question.
  def password_removable? = password_form_optional? || password_deferred?

  # Which ROWS may carry a NULL digest, as an expression the model can evaluate on
  # itself. Generated only where password_nullable? holds.
  #
  # Where the form called the password optional, that is every row and the answer
  # is a constant. Otherwise the form required one from everyone it collected, and
  # the rows excused are exactly the ones no form ever touched.
  def password_blank_rows_expression
    [("guest?" if guestable?), ("omniauth_identities.any?" if omniauth?)].compact.join(" || ")
  end

  # The same question asked of a sign-up in progress. A typed row came through a form
  # that asked for a password; a provider row holds the provider login instead.
  def staged_password_blank_rows_expression = pending_registration_holds_provider? ? "provider.present?" : "false"

  # Whether EVERY row may lack a password, on every model that includes the policy.
  # Where the form called the password optional or deferred it did so for everyone,
  # so no row is excused more than any other — and a predicate that cannot answer
  # anything but true is not a seam. PasswordPolicy drops the presence error flatly
  # and neither model generates #password_may_be_blank? at all.
  def password_blank_rows_all? = password_form_optional? || password_deferred?

  # Whether a guest is excused the phone-presence rule — the only place a SHARED
  # validation asks a row whether it is a guest. PendingRegistration defines
  # `guest? = false` to answer this and nothing else, so the stub follows it.
  #
  # Not simply guestable?: an optional phone has no presence rule to excuse, and the
  # format rule excuses nobody — allow_blank already skips the nil phone every guest carries.
  def guest_excused_from_phone? = guestable? && principals.phone&.required? || false

  # Too many failed sign-ins deadbolt the password door shut for a cooling-off window.
  #
  # The deadbolt defends the password and nothing else, so it bars the password door
  # and nothing else: a deadbolted account still signs in with its passkey, its magic
  # link, its provider. Barring those would buy nothing — the attacker never held
  # them — and would hand any stranger who knows an email address a switch for
  # locking its owner out of doors that were never under attack.
  #
  # It needs a guessable secret to count guesses against, so it needs a password:
  # a WebAuthn assertion either verifies or raises, and nobody brute-forces a
  # signed magic-link token. `--deadboltable` without `--password` is refused rather
  # than silently ignored.
  #
  # Enforced inside authenticate_with_password, where the password is checked, so
  # no sign-in door can forget it — no door does the checking. Not in the
  # start_new_session_for funnel: a deadbolt is not a fact about the account.
  def deadboltable? = options.deadboltable? && password?

  # An account can be suspended by an admin: barred from every sign-in door this
  # build has, with its live sessions destroyed. Distinct from --deadboltable, which
  # is automatic, password-only, and clears itself — a ban is a deliberate policy
  # action, so it carries its own state (banned_at, banned_until), its own admin
  # control, and its own unban path. The two never touch each other's column.
  # Enforced at the choke point every door funnels through (start_new_session_for),
  # because unlike a deadbolt a ban *is* a fact about the account. Always named to the
  # user — it's a message you mean to deliver — so it ignores --coy.
  #
  # A ban may carry an expiry (banned_until); banned? reads it, so a temporary ban
  # lifts itself with nothing scheduled to sweep it.
  def bannable? = options.bannable?

  def omniauth? = options.omniauth?

  # Required principals an OmniAuth provider can't supply: a username, a phone. Where
  # any exist, a provider sign-up is staged and a form collects them before the
  # account exists. Where none do, the callback creates the account itself.
  def omniauth_registration_principals
    principals.required.select { |p| %i[username phone].include?(p.type) }
  end

  def omniauth_registration? = omniauth? && omniauth_registration_principals.any?
  def omniauth_registration_collects_phone? = omniauth? && omniauth_registration_principals.any? { |p| p.type == :phone }

  # "username.blank? || phone.blank?": the provider row still owes its profile form.
  def omniauth_profile_missing_condition = omniauth_registration_principals.map { |p| "#{p.column}.blank?" }.join(" || ")

  # The omniauth registration form's permitted params — the columns the provider couldn't
  # supply (e.g. ":username"). Emitted into the registrations controller's permit.
  def omniauth_registration_permits
    omniauth_registration_principals.map { |p| ":#{p.column}" }.join(", ")
  end

  # What an emitted test types into that form.
  def omniauth_profile_params_literal
    values = omniauth_registration_principals.map { |p| p.type == :phone ? %(phone: "+14158264003") : %(#{p.column}: "provideruser") }
    "{ #{values.join(", ")} }"
  end

  # The form's number is proved by a texted code before the account exists.
  def omniauth_registration_verifies_phone? = omniauth_registration_collects_phone? && phone_verifiable?

  # The only door is a provider, so the callback is the only way an account is ever
  # made. A typed form here would collect an address the provider supplies anyway
  # and end at "now connect an account".
  def social_login_only? = omniauth? && !password? && !passkey? && !magic_link? && !sms_code?

  # The registration mode is one policy choice. Invitation modes generate the
  # invitation machinery; invite-only additionally gates every account-creating
  # flow on a still-pending invitation.
  def invitable? = %w[open-and-invites invite-only].include?(options[:registration])
  def invite_only? = options[:registration] == "invite-only"
  def email_invitable? = invitable? && !principals.email.nil?
  def phone_invitable? = invitable? && !principals.phone.nil?
  def multi_channel_invitable? = email_invitable? && phone_invitable?

  def invitation_recipient_label
    return "Email or phone" if multi_channel_invitable?

    email_invitable? ? "Email" : "Phone"
  end

  # A staged flow can mint an account from a phone invitation even where required
  # email means phone would never be the ordinary sign-up verification gate.
  def phone_registration_claim? = phone_gated_registration? || (pending_registration_model? && phone_invitable?)

  # Guests are anonymous, session-backed User rows.
  def guestable?     = options.guestable?

  # The admin boolean is its own concern; the admin UI and impersonation both need it.
  def adminable?     = options.adminable? || admin_dashboard? || impersonatable?
  def admin_dashboard? = options.admin_dashboard?
  def impersonatable? = options.impersonatable?

  # The enforced-MFA gate for admins only makes sense when both areas exist.
  def admin_mfa_gate? = admin_dashboard? && second_factor?

  # Where an MFA-less admin is held. The settings enrollment page for the factor
  # they can reach with nothing but a phone — TOTP where this build has it — so a
  # locked-out admin is never asked for hardware they may not be holding. Read by
  # the concern and by the tests.
  def admin_mfa_hold_path
    return "new_#{identity.settings_helper_prefix}_mfa_authenticator_path" if totp?
    return "new_#{identity.settings_helper_prefix}_mfa_sms_path" if sms_second_factor?

    "new_#{identity.settings_helper_prefix}_mfa_security_key_path"
  end

  # Authorization — role gates (admin) and per-resource access checks (team
  # membership) — lives in its own controller concern, separate from proving
  # identity (Authentication). Generated only when there's a gate to house.
  def authorization? = adminable? || teams?

  # ---------------------------------------------------------------------------
  # Ruby written into the generated TEST suite
  #
  # Nothing below reaches app code — every one of these is read only by a
  # template under templates/test_unit. Fixture passwords, sudo answers and the
  # sign-in gesture live here so a test template never has to ask which build
  # shape it is in.
  # ---------------------------------------------------------------------------

  # The body of an emitted test's `clear_sudo_bar` helper. Enrolling a credential is
  # guarded by require_sudo_within, so a test that enrols has to stamp sudo_at first —
  # once, since the window then covers the rest of the test. Without a password the
  # bar is a key once the account holds one, and nothing before; fixtures never hold
  # an enrolled authenticator, so the TOTP bar never comes up.
  def test_clear_sudo_body
    return "    # No bar to clear: this build has no sudo." unless sudoable?

    if sudo_bars.include?(:password)
      %(    post #{identity.route_scope}_sudo_path, params: { sudo_password: "quilted-lantern-moss-97" })
    else
      %(    post #{identity.route_scope}_sudo_path, params: { sudo_credential: #{identity.route_scope}_sudo_assertion } if @user.webauthn_credentials.any?)
    end
  end

  # The body of an emitted test's `sign_in_as(user)` helper, indented to sit inside
  # it. "Sign in" is not one gesture: a password build posts the form, a magic-link
  # build consumes a link, an --sms-code build asks for a code and types it back.
  # Every test template that needs a signed-in user shares this one choice.
  def test_sign_in_body
    if password?
      %(    post #{identity.route_scope}_sign_in_path, params: ) +
        %({ #{sign_in_field}: user.#{login_field}, password: "quilted-lantern-moss-97" })
    elsif magic_link?
      <<~RUBY.gsub(/^(?=.)/, "    ").chomp
        token = user.generate_magic_link
        patch #{identity.route_scope}_magic_link_path(sid: token)
      RUBY
    elsif sms_code?
      <<~RUBY.gsub(/^(?=.)/, "    ").chomp
        post #{identity.route_scope}_sms_sign_in_path, params: { phone: user.phone }
        # The code exists only in the outgoing text, so read it back from there.
        code = ActiveJob::Base.queue_adapter.enqueued_jobs.reverse
                              .filter_map { |job| job.to_s[/(\\d{6}) is your/, 1] }.first
        patch #{identity.route_scope}_sms_sign_in_code_path, params: { code: code }
      RUBY
    else
      # Passkey and omniauth have no gesture a hermetic test can perform, so this
      # build's door can't be driven at all. Mint the session directly instead and
      # hand the client the same signed cookie sign-in would have set, produced with
      # the app's own signing config. It is a stand-in for the door, not a test of it.
      #
      # Such a build also holds every request at the enrollment gate until a credential
      # exists, so the stand-in has to clear that too — a caller asking for a signed-in
      # user wants one who can actually reach a page.
      #
      # Deliberately ASCII-only. Thor reads templates with binread, so the ERB
      # buffer is BINARY; concatenating a UTF-8 string into one that already holds
      # a non-ASCII byte raises Encoding::CompatibilityError at generation time.
      #
      # The stand-in passkey is a real key held by @client, so the test can answer
      # a sudo bar with it (see configure_test_webauthn).
      lines =
        if stand_in_passkey?
          [
            "@client = WebAuthn::FakeClient.new(WebAuthn.configuration.allowed_origins.first)",
            "key = WebAuthn::Credential.from_create(@client.create(rp_id: WebAuthn.configuration.rp_id, user_verified: true))",
            %(user.webauthn_credentials.create!(name: "Test key", external_id: key.id, public_key: key.public_key#{factor_attr(:first_factor)}))
          ]
        else
          [%(user.omniauth_identities.create!(provider: "developer", uid: "uid-\#{user.id}"))]
        end
      lines += [
        "record = user.sessions.create!",
        %(env = Rails.application.env_config.merge("HTTP_HOST" => "www.example.com")),
        "jar = ActionDispatch::Request.new(env).cookie_jar",
        "jar.signed[:#{identity.cookie_name}] = record.id",
        "cookies[:#{identity.cookie_name}] = jar[:#{identity.cookie_name}]"
      ]
      lines.map { |line| "    #{line}" }.join("\n")
    end
  end

  # Whether a hermetic test can perform this build's sign-in gesture. Everything
  # else gets a minted session (see test_sign_in_body's last branch), which is
  # enough for tests ABOUT the signed-in area but not for tests about the act of
  # signing in — those assert on what the sign-in path itself does, and a stand-in
  # that never travels that path can't satisfy them.
  def test_drivable_door? = password? || magic_link? || sms_code?

  def stand_in_passkey? = passkey? && !test_drivable_door?

  # The principal half of a generated test's sign-up fixture. The interpolations
  # are escaped (`\#{`) so they survive into the emitted file intact: they belong
  # to the test, and run when it does, not while this generator writes it.
  def fixture_principal_entries(with_email:)
    entries = []
    entries << %(email: "new-\#{SecureRandom.hex(4)}@example.com") if with_email
    entries << %(username: "user_\#{SecureRandom.hex(4)}") if principals.username
    entries << %(phone: "+1415826\#{format('%04d', SecureRandom.random_number(10_000))}") if principals.phone
    entries
  end

  # What the emitted model test's build_<user> helper starts from.
  def account_fixture_literal(indent:)
    entries = fixture_principal_entries(with_email: !principals.email.nil?)
    entries << %(password: "quilted-lantern-moss-97") if password?
    hash_literal(entries, indent: indent)
  end

  # What the emitted controller test posts to sign up. Two differences from the
  # model fixture: an invite-only build's address comes from the invitation rather
  # than the form, and a form submits a confirmation beside the password.
  def sign_up_fixture_literal(indent:)
    entries = fixture_principal_entries(with_email: !principals.email.nil? && !invitation_pins_only_channel?)
    entries.concat([%(password: "quilted-lantern-moss-97"), %(password_confirmation: "quilted-lantern-moss-97")]) if password?
    hash_literal(entries, indent: indent)
  end

  # How an emitted test gives the fixture a way in that isn't its password, so the
  # removal guard stands down. Whichever non-password door this build actually has.
  def password_optional_second_door_setup
    if omniauth?
      %(@user.omniauth_identities.create!(provider: "developer", uid: "a-second-way-in"))
    elsif passkey?
      %(@user.webauthn_credentials.create!(name: "Key", external_id: "ext-second-way-in", public_key: "pk"#{factor_attr(:first_factor)}))
    else
      # --magic-link and --sms-code ride a principal the fixture already holds, so
      # there is nothing to create: the door is open the moment the account exists.
      "# #{magic_link? ? "the address" : "the number"} on file is already the second way in"
    end
  end

  # Put a second factor on a record directly, for tests that need one enrolled
  # rather than exercising the enrollment flow itself.
  # The challenge an emitted test lands on after the first factor: the one
  # enroll_second_factor_expr put on the fixture.
  def enrolled_second_factor_challenge_path
    return second_factor_challenge_path_for("totp") if totp?
    return second_factor_challenge_path_for("sms") if sms_second_factor?

    second_factor_challenge_path_for("security_keys")
  end

  def enroll_second_factor_expr(subject)
    return "#{subject}.update!(totp_enrolled_at: Time.current)" if totp?
    return "#{subject}.update!(sms_enrolled_at: Time.current)" if sms_second_factor?

    %(#{subject}.webauthn_credentials.create!(name: "Key", external_id: "ext-\#{#{subject}.id}", public_key: "pk"#{factor_attr(:second_factor)}))
  end

  # What an emitted *settings* test can expect when it hits a sudo-guarded action:
  # :answer when the fixture can meet the bar (see sudo_test_answer), :open when
  # there is no bar this account can be asked and sudo fails open.
  def sudo_test_mode = sudoable? && sudo_test_answer ? :answer : :open

  # The sudo answer a generated test sends with a guarded request. Fixture accounts
  # hold no authenticator enrollment, so the bars they can meet are the password and
  # the stand-in passkey's assertion; without either, sudo fails open. A TOTP bar is
  # deliberately absent: sudo_strategy poses it only to an enrolled account, so a
  # fixture carrying a totp_secret still clears sudo without answering, and sending
  # a code would look like coverage that isn't there.
  def sudo_test_answer
    return %(sudo_password: "quilted-lantern-moss-97") if sudo_bars.include?(:password)

    %(sudo_credential: #{identity.route_scope}_sudo_assertion) if stand_in_passkey?
  end

  # The sudo answer spliced into a generated test's params hash. Empty when the build
  # needs no answer.
  def sudo_test_params_pair = sudo_test_mode == :answer ? ", #{sudo_test_answer}" : ""

  # The credential fragment a guarded settings write (change your address, change
  # your number, delete your account) must carry: the sudo answer where those
  # controllers are guarded, or a password_challenge where they collect one
  # themselves.
  def settings_credential_pair
    return sudo_test_params_pair if sudoable?

    password? ? %(, password_challenge: "quilted-lantern-moss-97") : ""
  end

  # The OmniAuth callback path a generated test posts to (the route is unnamed, so
  # tests use the literal path). Namespaced identities carry it under their prefix, the
  # same place namespaced_omniauth_routes mounts the callbacks.
  def omniauth_callback_test_path
    prefix = "/#{identity.path_prefix}" if identity.namespaced?
    "#{prefix}/auth/developer/callback"
  end

  # The OmniAuth failure path a generated test hits (unnamed route, like the
  # callback above). Namespaced identities carry it under their prefix.
  def omniauth_failure_test_path
    prefix = "/#{identity.path_prefix}" if identity.namespaced?
    "#{prefix}/auth/failure"
  end

  # ---------------------------------------------------------------------------
  # Routes
  # ---------------------------------------------------------------------------

  def identity_scope_args
    path = %("#{identity.path_prefix}", ) if identity.namespaced?
    "#{path}module: :#{identity.controller_module}, as: :#{identity.route_scope}"
  end

  def route_block
    clean_route_block(<<~RUBY)
      scope #{identity_scope_args} do
        get "sign_in", to: "sessions#new"#{password? ? %(\n  post "sign_in", to: "sessions#create") : ""}
        delete "sign_out", to: "sessions#destroy"
      #{user_scope_route_blocks}end

      #{settings_namespace}
      #{top_level_route_blocks}
    RUBY
  end

  # The namespaced shape: one outer scope, path-prefixed under the identity's own
  # name, wraps *everything* — doors, settings, teams, admin, omniauth callbacks —
  # plus a subroot (<identity>_root_path). That is what keeps a second identity
  # from colliding with the first on bare paths like /sign_in or /admin.
  def namespaced_route_block
    clean_route_block(<<~RUBY)
      scope #{identity_scope_args} do
        get "sign_in", to: "sessions#new"#{password? ? %(\n  post "sign_in", to: "sessions#create") : ""}
        delete "sign_out", to: "sessions#destroy"
      #{user_scope_route_blocks}
      #{settings_namespace(indent: 2)}
      #{namespaced_omniauth_routes if omniauth?}
      #{area_route_blocks.gsub(/^(?=.)/, "  ")}
        root to: "settings/dashboard#index"
      end
      #{namespaced_top_level_route_blocks}
    RUBY
  end

  def area_route_blocks
    route_blocks(
      (team_routes if teams?),
      (admin_routes if admin_dashboard?)
    )
  end

  def user_scope_route_blocks
    route_blocks(
      (registration_routes if typed_registration?),
      (email_verification_routes if email_verifiable?),
      (password_reset_routes if recoverable?),
      (magic_link_routes if magic_link?),
      (sms_code_routes if sms_code?),
      (phone_verification_routes if phone_gated_registration?),
      (passkey_routes if passkey?),
      (credential_enrollment_routes if credential_staged_registration?),
      (sudo_routes if sudoable?),
      (mfa_challenge_routes if second_factor?),
      trailing: true
    )
  end

  # The settings namespace's optional resources, indented to sit inside it. The
  # individual builders emit at column 0 and are shifted here in one place,
  # because the namespace sits at a different depth in the two route shapes:
  # top level by default, one level in once namespaced.
  def settings_route_blocks(indent)
    blocks = route_blocks(
      (settings_invitation_route if invitable?),
      (mfa_profile_routes if second_factor?),
      (passkey_profile_routes if passkey?),
      (omniauth_profile_routes if omniauth?),
      (authentication_event_routes if trackable?),
      trailing: true
    )
    blocks.gsub(/^(?=.)/, " " * indent)
  end

  def top_level_route_blocks
    route_blocks(
      area_route_blocks,
      (omniauth_routes if omniauth?),
      (invitation_routes if invitable?),
      (easy_dev_login_routes if easy_dev_login? && !password?)
    )
  end

  # What a namespaced identity leaves outside its scope. Its omniauth callbacks, teams
  # and admin area move inside, where a second identity can't collide with them.
  def namespaced_top_level_route_blocks
    route_blocks(
      (namespaced_invitation_routes if invitable?),
      (easy_dev_login_routes if easy_dev_login? && !password?)
    )
  end

  def route_blocks(*blocks, trailing: false)
    routes = blocks.compact.map(&:chomp).reject(&:empty?).join("\n")
    routes += "\n" if trailing && !routes.empty?
    routes
  end

  # The self-service settings area: a landing page plus the :settings namespace
  # holding every account-management resource. One builder serves both route
  # shapes, since only its depth differs — +indent+ 0 for the default identity,
  # which mounts it at the top level (/settings -> Settings::...), and 2 once
  # namespaced, where it nests inside the identity's own outer scope, inheriting
  # that scope's module and as: (/realtors/settings -> Realtors::Settings::...).
  def settings_namespace(indent: 0)
    pad  = " " * indent
    body = " " * (indent + 2)

    lines = [%(#{pad}get "settings", to: "settings/dashboard#index"), "#{pad}namespace :settings do"]
    # :create sets a FIRST password on an account minted without one; :destroy
    # gives one up. Different questions — a required build still needs :create for
    # its provider and guest rows, and still offers no way out.
    password_actions = [":edit", ":update", (":create" if password_nullable?), (":destroy" if password_removable?)].compact
    lines << "#{body}resource :password, only: [ #{password_actions.join(", ")} ]" if password?
    lines << "#{body}resource :email, only: [ :edit, :update ]" if email_changeable?
    lines << "#{body}resource :phone, only: [ :edit, :update ]" if phone_changeable?
    lines << "#{body}resource :user, only: [ :show, :destroy ]"
    # Only the change resend lives under /settings. Its link is consumed by
    # the identity's own EmailVerificationsController at the top level, because the inbox may
    # be read on a different device with no session. Staged sign-up links use the
    # sibling Registrations::EmailVerificationsController for their different
    # collision rule.
    lines << "#{body}resource :email_verification, only: [ :create ]" if email_change_verification?
    lines << "#{body}resource :phone_verification, only: [ :new, :create, :update ]" if phone_change_verification?
    lines << "#{body}resources :sessions, only: [ :index, :destroy ]"
    lines << "#{body}resources :api_tokens, only: [ :index, :create, :destroy ]" if api_tokens?

    extras = settings_route_blocks(indent + 2).chomp
    lines << extras unless extras.empty?

    lines << "#{pad}end"
    lines.join("\n")
  end

  def clean_route_block(routes)
    align_route_lines(routes.lines.map(&:rstrip)).join("\n")
  end

  # Squares up the columns in a finished route block: the first argument, and
  # whatever follows the first comma (`to:`, `only:`, ...).
  #
  # It happens here, after assembly, because no builder above can do it. Which
  # routes a block contains depends on the flags, so padding written by hand is
  # padding aimed at a line that may not be generated — and when it isn't, the
  # leftover spaces align with nothing, which is exactly what RuboCop's
  # Layout/SpaceBeforeFirstArg objects to (`get  "sign_in"` is fine beside a
  # `post "sign_in"` and a stray double space without it). Aligning once, when the
  # membership of each group is finally known, is the only way to be right in
  # every build.
  #
  # A group is a run of adjacent route calls sharing one indent. Anything else
  # breaks it — a blank line, a comment, an `end`, a block opener (`... do`, whose
  # body sits a level deeper and lines up on its own).
  def align_route_lines(lines)
    lines
      .slice_when { |before, after| !same_route_group?(before, after) }
      .flat_map { |group| align_route_group(group) }
  end

  def same_route_group?(before, after)
    parts = route_line_parts(before)
    parts && route_line_parts(after)&.fetch(:indent) == parts[:indent]
  end

  def align_route_group(group)
    parts = group.map { |line| route_line_parts(line) }
    return group unless parts.all?

    method_width = parts.map { |part| part[:method].length }.max
    option_width = parts.filter_map { |part| part[:argument].length if part[:options] }.max || 0

    parts.map do |part|
      line = "#{part[:indent]}#{part[:method].ljust(method_width)} #{part[:argument]}"
      line << "#{" " * (option_width - part[:argument].length + 1)}#{part[:options]}" if part[:options]
      line
    end
  end

  # Splits one route call into the pieces the aligner pads between, or nil for a
  # line that isn't one (a comment, a blank, an `end`, a block opener).
  def route_line_parts(line)
    return nil if line.end_with?(" do")

    match = /\A(?<indent> *)(?<method>[a-z_]+) +(?<rest>\S.*)\z/.match(line)
    return nil unless match

    argument, separator, options = match[:rest].partition(", ")
    return { indent: match[:indent], method: match[:method], argument: argument, options: nil } if separator.empty?

    { indent: match[:indent], method: match[:method], argument: "#{argument},", options: options.lstrip }
  end

  def primary_key_options
    return "" unless primary_key_type

    ", id: #{primary_key_type.to_sym.inspect}"
  end

  def reference_type_options
    return "" unless primary_key_type

    ", type: #{primary_key_type.to_sym.inspect}"
  end

  def primary_key_type
    configured_primary_key_type =
      options[:primary_key_type] ||
      active_record_generator_options[:primary_key_type] ||
      active_record_generator_options["primary_key_type"]

    configured_primary_key_type&.to_s
  end

  def active_record_generator_options
    Rails::Generators.options[:active_record] || {}
  end

  def registration_routes
    <<~RUBY.gsub(/^/, "  ")

      get "sign_up", to: "registrations#new"
      post "sign_up", to: "registrations#create"
    RUBY
  end

  def sudo_routes
    <<~RUBY.gsub(/^/, "  ")

      resource :sudo, only: [ :new, :create ]
    RUBY
  end

  def easy_dev_login_routes
    <<~RUBY

      if Rails.env.development?
        scope #{identity_scope_args} do
          post "easy_dev_login", to: "easy_dev_logins#create"
        end
      end
    RUBY
  end

  def settings_invitation_route
    <<~RUBY
      resource :invitation, only: [ :new, :create ]
    RUBY
  end

  def authentication_event_routes
    <<~RUBY
      namespace :authentications do
        resources :events, only: :index
      end
    RUBY
  end

  def invitation_routes
    routes = [%(get "invitations/accept", to: "invitations#show", as: :accept_invitation)]
    routes << %(patch "invitations/accept", to: "invitations#update") if teams?
    "\n#{routes.join("\n")}\n"
  end

  # Routed at the top level (outside the identity's own scope) like
  # invitation_routes above, but path-prefixed and pointing at this identity's own
  # namespaced controller and route helper. Both must differ from the incumbent's:
  # the path so the accept link reaches this identity (a bare "invitations/accept"
  # collides with the incumbent's identical path and Rails dispatches the first),
  # and the controller must be named in full in `to:` — an inline `module:` option
  # alongside a string `to:` does NOT namespace it (it leaks in as a stray param
  # and the bare InvitationsController handles the request), so spell it out.
  def namespaced_invitation_routes
    path = "#{identity.path_prefix}/invitations/accept"
    routes = [%(get "#{path}", to: "#{identity.controller_module}/invitations#show", as: :#{identity.route_scope}_accept_invitation)]
    routes << %(patch "#{path}", to: "#{identity.controller_module}/invitations#update") if teams?
    "\n#{routes.join("\n")}\n"
  end

  def omniauth_routes
    registration = <<~RUBY.chomp if omniauth_registration?

      scope "auth", as: :#{identity.route_scope}_omniauth do
        resource :registration, only: [ :new, :create ], controller: "#{identity.controller_module}/omniauth/registrations"
      end
    RUBY
    <<~RUBY

      post "/auth/:provider/callback", to: "#{identity.controller_module}/omniauth#create"
      get "/auth/:provider/callback", to: "#{identity.controller_module}/omniauth#create"
      get "/auth/failure", to: "#{identity.controller_module}/omniauth#failure"#{registration}
    RUBY
  end

  # Same routes as omniauth_routes, but relative: this variant lives *inside*
  # namespaced_route_block's `scope "...", module: ... do`, which already supplies
  # both the path prefix and the controller module, so /realtor/auth/... is
  # free and "omniauth#create" (not "realtors/omniauth#create") resolves
  # correctly.
  def namespaced_omniauth_routes
    registration = <<~RUBY.chomp if omniauth_registration?

      scope "auth", as: :omniauth do
        resource :registration, only: [ :new, :create ], controller: "omniauth/registrations"
      end
    RUBY
    <<~RUBY.gsub(/^/, "  ")

      post "auth/:provider/callback", to: "omniauth#create"
      get "auth/:provider/callback", to: "omniauth#create"
      get "auth/failure", to: "omniauth#failure"#{registration}
    RUBY
  end

  def password_reset_routes
    <<~RUBY.gsub(/^/, "  ")

      get "forgot_password", to: "password_resets#new"
      post "reset_password", to: "password_resets#create"
      get "reset_password", to: "password_resets#edit"
      patch "reset_password", to: "password_resets#update"
      put "reset_password", to: "password_resets#update"
    RUBY
  end

  # Email sign-up and account change have different collision rules, so their
  # links land at separate endpoints even though both remain reachable signed-out.
  # A permanent email keeps the sign-up half and drops the change half, which is
  # why the two are assembled separately rather than as one heredoc.
  def email_verification_routes
    lines = []

    # The sign-up click carries its own proof at /verify_email, where GET only
    # renders the confirm button and PATCH does the work — a mail scanner's GET
    # must not be able to consume the link. /new remains the waiting page and
    # POST remains its resend action.
    if email_gated_registration?
      lines.push(
        %(get "verify_email", to: "registrations/email_verifications#show"),
        %(patch "verify_email", to: "registrations/email_verifications#update"),
        %(get "verify_email/new", to: "registrations/email_verifications#new", as: :new_verify_email),
        %(post "verify_email", to: "registrations/email_verifications#create")
      )
    end
    lines << %(get "verify_email_change", to: "email_verifications#show") if email_change_verification?
    lines << %(patch "verify_email_change", to: "email_verifications#update") if email_change_verification?
    return "" if lines.empty?

    lines.map { "  #{it}\n" }.join.prepend("\n")
  end

  # Where a phone-gated sign-up finishes. Unauthenticated by construction — the
  # visitor has no session yet, which is the whole point.
  def phone_verification_routes
    <<~RUBY.gsub(/^/, "  ")

      get "verify_phone", to: "registrations/phone_verifications#new"
      post "verify_phone", to: "registrations/phone_verifications#create"
      patch "verify_phone", to: "registrations/phone_verifications#update"
    RUBY
  end

  def magic_link_routes
    <<~RUBY.gsub(/^/, "  ")

      get "magic_link", to: "magic_link#edit"
      patch "magic_link", to: "magic_link#update"
      get "magic_link/new", to: "magic_link#new", as: :new_magic_link
      post "magic_link", to: "magic_link#create"
    RUBY
  end

  # Passwordless sign-in by texted code. Two steps, two paths: the request form
  # takes a number, the code form takes the six digits. Both unauthenticated by
  # construction — there is no session until the code is redeemed — which is why
  # what links them is a signed token in the session rather than a URL param.
  def sms_code_routes
    <<~RUBY.gsub(/^/, "  ")

      get "sms_sign_in", to: "sms_sessions#new"
      post "sms_sign_in", to: "sms_sessions#create"
      get "sms_sign_in/code", to: "sms_sessions#edit", as: :sms_sign_in_code
      patch "sms_sign_in/code", to: "sms_sessions#update"
    RUBY
  end

  # Passwordless passkey sign-in (the primary door). #new returns the assertion
  # challenge as JSON; #create verifies the signed assertion and starts the
  # session. Lives under the users scope like the other doors.
  def passkey_routes
    <<~RUBY.gsub(/^/, "  ")

      namespace :passkeys do
        resource :session, only: [ :new, :create ]
      end
    RUBY
  end

  # Initial credentials belong to the pending registration, before any session
  # exists. Emit only the endpoints this build can actually reach.
  def credential_enrollment_routes
    lines = []
    lines << %(get "finish_setup", to: "credential_enrollments#show") if registration_credential_page?
    if pre_account_password_enrollment?
      lines << %(get "registration/password", to: "credential_enrollments/passwords#new", as: :new_registration_password)
      lines << %(post "registration/password", to: "credential_enrollments/passwords#create", as: :registration_password)
    end
    if pre_account_passkey_enrollment?
      lines << %(get "registration/passkey", to: "credential_enrollments/passkeys#new", as: :new_registration_passkey)
      lines << %(post "registration/passkey", to: "credential_enrollments/passkeys#create", as: :registration_passkey)
    end
    lines.map { "  #{it}\n" }.join.prepend("\n")
  end

  # Manage your own passkeys (list / enroll / rename / remove), separate from the
  # MFA security-keys page.
  def passkey_profile_routes
    <<~RUBY
      resources :passkeys, only: [ :index, :new, :create, :edit, :update, :destroy ]
    RUBY
  end

  # List and unlink your provider logins. There is no :new and no :create — linking
  # runs the same OmniAuth ceremony signing in does, so it goes out through
  # /auth/:provider and comes back to the callback, which links it because a
  # session is already open. The index just renders the buttons that start it.
  def omniauth_profile_routes
    <<~RUBY
      resources :omniauth_identities, path: "connected-accounts", only: [ :index, :destroy ]
    RUBY
  end

  def mfa_challenge_routes
    <<~RUBY.gsub(/^/, "  ")

      namespace :multi_factor_authentication, path: "mfa", as: :mfa do
        namespace :challenge do#{totp? ? "\n    resource :totp, only: [ :new, :create ]" : ""}#{sms_second_factor? ? "\n    resource :sms, only: [ :new, :create, :update ]" : ""}
          resource :recovery_codes, only: [ :new, :create ]#{security_keys? ? "\n    resource :security_keys, only: [ :new, :create ]" : ""}
        end
      end
    RUBY
  end

  def mfa_profile_routes
    <<~RUBY
      namespace :multi_factor_authentication, path: "mfa", as: :mfa do
      #{mfa_profile_authenticator_routes}#{mfa_profile_sms_routes}  resources :recovery_codes, only: [ :index, :create ] do
          post :complete, on: :collection
        end
      #{mfa_profile_security_key_routes}end
    RUBY
  end

  def mfa_profile_authenticator_routes
    return "" unless totp?

    "  resource :authenticator, only: [ :new, :show, :create, :destroy ]\n"
  end

  def mfa_profile_sms_routes
    return "" unless sms_second_factor?

    "  resource :sms, only: [ :new, :show, :create, :update, :destroy ]\n"
  end

  def mfa_profile_security_key_routes
    return "" unless security_keys?

    "  resources :security_keys\n"
  end

  def team_routes
    routes = ["resources :teams, only: [ :index, :new, :create ]"]
    routes << "resource :active_team, only: :create" if session_carries_team?
    routes << <<~RUBY.chomp if scope_teams?
      scope ":team_id", as: :team, constraints: { team_id: #{team_id_constraint} } do
        root to: "teams#show"
      end
    RUBY

    "\n#{routes.join("\n")}\n"
  end

  def admin_routes
    impersonation_routes =
      if impersonatable?
        <<~RUBY.gsub(/^/, "  ")
          post "users/:id/impersonate", to: "users#impersonate", as: "impersonate_user"
        RUBY
      else
        ""
      end

    # Stopping sits outside the admin namespace on purpose — see
    # ImpersonationsController. Starting is an admin action; stopping isn't.
    stop_impersonating_route = impersonatable? ? %(\nresource :impersonation, only: [ :destroy ]\n) : ""

    member_posts = []
    member_posts << "reset_second_factor" if second_factor?
    # Undeadbolt only: deadbolting is the failed-attempt counter's job, and an admin who
    # wants to shut an account off reaches for a ban.
    member_posts << "undeadbolt" if deadboltable?
    member_posts += %w[ban unban] if bannable?
    member_actions = member_posts.map { |a| "\n    post :#{a}, on: :member" }.join

    <<~RUBY

      namespace :admin do
        resources :users, only: [ :index, :show, :destroy ] do
          delete :sessions, on: :member, action: :destroy_all_sessions#{member_actions}
        end
        resources :sessions, only: [ :index, :destroy ]
      #{impersonation_routes}  root to: "dashboard#index"
      end
    RUBY
      .concat(stop_impersonating_route)
  end
end
