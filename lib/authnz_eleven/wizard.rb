# frozen_string_literal: true

require_relative "../authnz_eleven"

module AuthnzEleven
  # An interactive flag picker for the main generator.
  #
  # The generator has forty-odd flags and a dozen validators explaining which
  # combinations don't work. Those validators exist because a command line
  # arrives all at once. A wizard asks in dependency order instead, so a
  # combination the generator would refuse is simply never offered: the answers
  # to one screen decide what the next screen contains.
  #
  # That ordering is the whole design. Principals before doors, because a door
  # needs something to deliver to. Verification before the password mode,
  # because `deferred` waits on a proved channel. Teams and admin last, because
  # nothing upstream depends on them.
  class Wizard
    # Flags that turn another one on by themselves, so naming both in the
    # emitted command would be noise.
    IMPLIED = {
      "admin_dashboard" => "adminable",
      "impersonatable" => "adminable"
    }.freeze

    # The answers are seeded with the recommended explicit principal and the
    # generator's behavioral defaults.
    class Answers
      attr_accessor :user_class, :namespaced,
                    :email, :phone, :username,
                    :contactable, :verify, :coy, :encrypted,
                    :doors, :registration, :permanent, :password_mode, :password_extras,
                    :second_factor, :protections,
                    :sessions, :max_sessions, :api_tokens, :teams, :admin

      def initialize
        @user_class = "User"
        @namespaced = false
        @email = "required"
        @phone = "none"
        @username = false
        @contactable = true
        @verify = true
        @coy = false
        @encrypted = false
        @doors = []
        @registration = "open"
        @permanent = []
        @password_mode = "required"
        @password_extras = []
        @second_factor = []
        @protections = []
        @sessions = []
        @max_sessions = "none"
        @api_tokens = false
        @teams = "none"
        @admin = []
      end

      def email? = email != "none"
      def phone? = phone != "none"

      # The requiredness words of the channels this build actually has, so the
      # channel rules can be asked of the set rather than of each column.
      def channels = [email, phone].reject { |mode| mode == "none" }
      def channels? = channels.any?
      def optional_channel? = channels.include?("optional")

      # One channel, and it may be absent: nothing for "optional" to be optional
      # against, so an account could hold no way to be reached at all.
      def sole_optional_channel? = channels == ["optional"]

      def password? = doors.include?("password")
      def sms_code? = doors.include?("sms_code")
      def other_doors? = doors.any? { |d| d != "password" }

      # Mirrors the generator's validate_password_deferred!.
      def password_deferrable? = doors.include?("passkey") || (contactable && verify && channels?)

      # Mirrors the generator's validate_sudoable!.
      def sudo_answerable? = password? || doors.include?("passkey") || second_factor.intersect?(%w[totp webauthn])

      def email_verifiable? = verify && email?
      def phone_verifiable? = verify && phone?

      # Mirrors the generator's validate_coy!.
      def coyable? = verify && channels?

      # "Permanent" removes the settings form for a value, which only reads as a
      # rule when the value was there from the start: every sign-up path collects
      # a required phone before the account exists.
      def phone_permanent? = phone == "required"
    end

    def initialize
      @answers = Answers.new
    end

    attr_reader :answers

    def run
      require "huh"

      errors = form.run
      raise Error, errors.map(&:message).join("; ") if errors.any?

      to_flags
    end

    def to_flags
      [
        *identity_flags,
        *principal_flags,
        *channel_flags,
        *door_flags,
        *feature_flags
      ]
    end

    def command = ["bin/rails generate authnz_eleven", *to_flags].join(" ")

    private

    # Every screen's options are plain [label, value] pairs, so which options a
    # build offers can be asked without a terminal — or the form library — in
    # the room. `menu` is the only place they become Huh objects.
    def menu(pairs) = pairs.map { |label, value| Huh.option(label, value) }

    EMAIL_MODES = [
      %w[Required required],
      %w[Optional optional],
      %w[None none]
    ].freeze

    PHONE_MODES = [
      %w[Required required],
      %w[Optional optional],
      %w[None none]
    ].freeze

    SECOND_FACTORS = [
      ["Authenticator app (TOTP)", "totp"],
      ["Hardware security key (WebAuthn)", "webauthn"],
      ["Texted code (SMS)", "sms"]
    ].freeze

    PROTECTIONS = [
      ["Captcha on signed-out forms (Cloudflare Turnstile)", "captchable"],
      ["Ask users to authenticate again before dangerous actions (sudo)", "sudoable"],
      ["Email users when security settings change", "security_notifications"]
    ].freeze

    SESSIONS = [
      ["'Remember me' checkbox", "rememberable"],
      ["Sign out inactive users", "timeoutable"],
      ["Record when users were last seen", "last_seenable"],
      ["Audit trail of authentication activity", "trackable"],
      ["Anonymous guest users", "guestable"],
      ["Sign in as anyone (development only)", "easy_dev_login"]
    ].freeze

    MAX_SESSIONS = [
      ["No limit", "none"],
      ["Sign out the oldest", "evict"],
      ["Ask the user to sign one out", "prompt"]
    ].freeze

    TEAMS = [
      ["No teams", "none"],
      ["Team stored in the session", "session"],
      ["Team in the URL (/:team_id)", "scope"],
      ["Team in the URL, via middleware (37signals-style)", "middleware"]
    ].freeze

    ADMIN = [
      ["Admin users", "adminable"],
      ["An /admin area", "admin_dashboard"],
      ["Admins can impersonate users", "impersonatable"],
      ["Admins can ban users", "bannable"]
    ].freeze

    def form
      Huh.form(
        identity_group,
        namespaced_group,
        principals_group,
        contactable_group,
        channels_group,
        coy_group,
        doors_group,
        registration_group,
        permanence_group,
        password_group,
        protections_group,
        sessions_group,
        api_tokens_group,
        teams_group,
        admin_group
      ).with_theme(Huh::Themes.base16)
    end

    # ---- screens -------------------------------------------------------

    def identity_group
      Huh.group(
        Huh.input
          .key("user_class")
          .title("What is the signed-in model called?")
          .description("The table, routes and controllers are named after it.")
          .placeholder("User")
          .value(answers, :user_class)
      ).title("Identity")
    end

    # Only a second identity needs a URL prefix, and a second identity is the
    # only reason to name the model something other than User.
    def namespaced_group
      Huh.group(
        Huh.confirm
          .key("namespaced")
          .title("Give this identity its own URL prefix and namespace?")
          .description("Required if your app already has one.")
          .value(answers, :namespaced)
      ).title("Namespace").with_hide_func { answers.user_class == "User" }
    end

    def principals_group
      Huh.group(
        Huh.select
          .key("email")
          .title("Email")
          .options(*menu(EMAIL_MODES))
          .value(answers, :email),
        Huh.select
          .key("phone")
          .title("Phone")
          .options(*menu(PHONE_MODES))
          .value(answers, :phone),
        Huh.confirm
          .key("username")
          .title("Username?")
          .value(answers, :username)
          .validate { |username| validate_identifier(username) }
      ).title("Identifiers")
         .description("What users sign in with.")
         .with_validate_on_submit(true)
    end

    # Drop the email column and something else has to name the account at the
    # sign-in form. Asked here rather than left to the generator because the
    # answer is two fields up on the screen the user is already looking at.
    def validate_identifier(username)
      return if answers.email? || username || answers.phone.start_with?("required")

      raise Huh::ValidationError,
            "without email, add a username or make phone required"
    end

    # "Optional" only means something when another channel covers the gap.
    # With every channel required the promise is already kept, so don't ask.
    def contactable_group
      Huh.group(
        Huh.confirm
          .key("contactable")
          .title("Must every account have an email or phone?")
          .description("Say no for old-school accounts you can't contact or recover.")
          .value(answers, :contactable)
          .validate { |contactable| validate_contactable(contactable) }
      ).title("Contact")
         .with_hide_func { !answers.optional_channel? }
         .with_validate_on_submit(true)
    end

    # With a second channel to fall back on, "optional" and "must hold one" agree.
    # With only one, they contradict each other and the flag would be a lie.
    def validate_contactable(contactable)
      return unless contactable && answers.sole_optional_channel?

      raise Huh::ValidationError,
            "your only email/phone is optional, so answer no or make it required"
    end

    def channels_group
      Huh.group(
        Huh.confirm
          .key("verify")
          .title("Verify emails and phone numbers?")
          .description("By emailed link or texted code.")
          .value(answers, :verify),
        Huh.confirm
          .key("encrypted")
          .title("Encrypt emails and phone numbers at rest?")
          .value(answers, :encrypted)
      ).title("Email and phone").with_hide_func { !answers.channels? }
    end

    def coy_group
      Huh.group(
        Huh.confirm
          .key("coy")
          .title("Hide whether an account exists?")
          .description("Forms respond the same whether or not an email or phone is registered.")
          .value(answers, :coy)
      ).title("Account privacy").with_hide_func { !answers.coyable? }
    end

    def doors_group
      Huh.group(
        Huh.multi_select
          .key("doors")
          .title("How do users sign in?")
          .options_func { menu(door_options) }
          .value(answers, :doors)
          .validate { |chosen| validate_doors(chosen) }
      ).title("Sign-in").with_validate_on_submit(true)
    end

    # A door needs somewhere to deliver to: magic links ride email, codes ride SMS.
    def door_options
      [
        %w[Password password],
        %w[Passkey passkey],
        ["Social / SSO (OmniAuth)", "omniauth"],
        (["Emailed link", "magic_link"] if answers.email?),
        (["Texted code", "sms_code"] if answers.phone?)
      ].compact
    end

    # A texted second factor needs a number to text, and is pointless beside the
    # texted door: same proof of the same phone, so whoever holds the number has
    # already opened the door.
    def second_factor_options
      return SECOND_FACTORS if answers.phone? && !answers.sms_code?

      SECOND_FACTORS.reject { |_, value| value == "sms" }
    end

    def protection_options
      PROTECTIONS.reject do |_, value|
        value == "sudoable" && !answers.sudo_answerable? ||
          value == "security_notifications" && !answers.email?
      end
    end

    def validate_doors(chosen)
      raise Huh::ValidationError, "pick at least one way to sign in" if chosen.empty?

      return unless chosen == ["sms_code"] && answers.phone == "optional"

      raise Huh::ValidationError,
            "texted codes are the only sign-in method, so make phone required or add another method"
    end

    # Registration is one choice with four possible account-creation policies.
    # An invitation has to be sent somewhere, so the two invite answers need a
    # channel.
    def registration_group
      Huh.group(
        Huh.select
          .key("registration")
          .title("Who can create an account?")
          .options_func { menu(registration_options) }
          .value(answers, :registration)
      ).title("Registration")
    end

    def registration_options
      [
        ["Nobody. You create accounts yourself", "closed"],
        %w[Anyone open],
        (["Anyone, and users can invite others", "open-and-invites"] if answers.channels?),
        (["Invited users only", "invite-only"] if answers.channels?)
      ].compact
    end

    # Asked here, well after the principals themselves, because whether a number
    # CAN be permanent depends on the doors and the registration mode: a build
    # that mints the account before the number arrives has to keep the settings
    # form that permanence removes.
    def permanence_group
      Huh.group(
        Huh.multi_select
          .key("permanent")
          .title("Which can users never change?")
          .description("Admins can still change them.")
          .options_func { menu(permanent_options) }
          .value(answers, :permanent)
      ).title("Permanent").with_hide_func { permanent_options.empty? }
    end

    def permanent_options
      [
        (%w[Email email] if answers.email == "required"),
        (%w[Phone phone] if answers.phone_permanent?)
      ].compact
    end

    def password_group
      Huh.group(
        Huh.select
          .key("password_mode")
          .title("Password on the sign-up form")
          .options_func { menu(password_mode_options) }
          .value(answers, :password_mode),
        Huh.multi_select
          .key("password_extras")
          .title("Password features")
          .options_func { menu(password_extra_options) }
          .value(answers, :password_extras)
      ).title("Password").with_hide_func { !answers.password? }
    end

    # A password reset is an emailed link, so it rides the email channel.
    def password_extra_options
      [
        (["Password reset by email", "recoverable"] if answers.email?),
        ["Reject breached passwords", "pwned"],
        ["Reject weak passwords", "strong_passwords"],
        ["Change passwords every 90 days", "password_rotatable"],
        ["Reject reused passwords", "password_historical"],
        ["Shut password sign-in for a while after too many failures", "deadboltable"]
      ].compact
    end

    def password_mode_options
      [
        %w[Required required],
        (%w[Optional optional] if answers.other_doors?),
        (["Asked for on a second page", "deferred"] if answers.password_deferrable?)
      ].compact
    end

    def protections_group
      Huh.group(
        Huh.multi_select
          .key("second_factor")
          .title("Two-factor authentication")
          .options_func { menu(second_factor_options) }
          .value(answers, :second_factor),
        Huh.multi_select
          .key("protections")
          .title("Other protections")
          .options_func { menu(protection_options) }
          .value(answers, :protections)
      ).title("Protections")
    end

    def sessions_group
      Huh.group(
        Huh.multi_select
          .key("sessions")
          .title("Session features")
          .options(*menu(SESSIONS))
          .value(answers, :sessions),
        Huh.select
          .key("max_sessions")
          .title("Limit sessions per user?")
          .options(*menu(MAX_SESSIONS))
          .value(answers, :max_sessions)
      ).title("Sessions")
    end

    def api_tokens_group
      Huh.group(
        Huh.confirm
          .key("api_tokens")
          .title("Issue personal access tokens for your application's API?")
          .description("Adds browser settings to manage tokens and a separate concern for API controllers.")
          .value(answers, :api_tokens)
      ).title("API tokens")
    end

    def teams_group
      Huh.group(
        Huh.select
          .key("teams")
          .title("Teams")
          .options(*menu(TEAMS))
          .value(answers, :teams)
      ).title("Teams")
    end

    def admin_group
      Huh.group(
        Huh.multi_select
          .key("admin")
          .title("Administration")
          .options(*menu(ADMIN))
          .value(answers, :admin)
      ).title("Administration")
    end

    # ---- emitting ------------------------------------------------------

    def identity_flags
      [
        ("--user-class=#{answers.user_class}" unless answers.user_class == "User"),
        ("--namespaced" if answers.namespaced)
      ].compact
    end

    def principal_flags
      [
        ("--email=#{mode(:email)}" unless mode(:email) == "none"),
        ("--phone=#{mode(:phone)}" unless mode(:phone) == "none"),
        ("--username" if answers.username)
      ].compact
    end

    def mode(channel)
      value = answers.public_send(channel)
      answers.permanent.include?(channel.to_s) ? "#{value},permanent" : value
    end

    def channel_flags
      [
        ("--no-verifiable" unless answers.verify),
        ("--coy" if answers.coy && answers.coyable?),
        ("--no-contactable" unless answers.contactable),
        ("--encrypted-pii" if answers.encrypted)
      ].compact
    end

    def door_flags
      answers.doors.map { |door| door == "password" ? password_flag : flag(door) }
    end

    def password_flag
      answers.password_mode == "required" ? "--password" : "--password=#{answers.password_mode}"
    end

    REGISTRATION = {
      "closed" => ["--registration=closed"],
      "open" => [],
      "open-and-invites" => ["--registration=open-and-invites"],
      "invite-only" => ["--registration=invite-only"]
    }.freeze

    def feature_flags
      [
        *REGISTRATION.fetch(answers.registration),
        *(answers.password? ? answers.password_extras.map { |e| flag(e) } : []),
        ("--second-factor=#{answers.second_factor.join(",")}" if answers.second_factor.any?),
        *answers.protections.map { |p| flag(p) },
        *answers.sessions.map { |s| flag(s) },
        *max_sessions_flag,
        ("--api-tokens" if answers.api_tokens),
        *teams_flag,
        *admin_flags
      ].compact
    end

    def max_sessions_flag
      return [] if answers.max_sessions == "none"

      [answers.max_sessions == "evict" ? "--max-sessionable" : "--max-sessionable=prompt"]
    end

    def teams_flag
      { "none" => [], "session" => ["--teams=session"], "scope" => ["--teams"],
        "middleware" => ["--teams=middleware"] }.fetch(answers.teams)
    end

    def admin_flags
      (answers.admin - answers.admin.filter_map { |a| IMPLIED[a] }).map { |a| flag(a) }
    end

    def flag(name) = "--#{name.tr("_", "-")}"
  end
end
