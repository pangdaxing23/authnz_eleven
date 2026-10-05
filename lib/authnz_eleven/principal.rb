# frozen_string_literal: true

module AuthnzEleven
  # One piece of identifying information on the generated account. A Principal
  # derives every name and expression the templates need for one identifying
  # attribute (email, username, phone), so the per-type differences live here
  # instead of being scattered across the templates.
  #
  # Each selected principal is an explicit part of the generated account shape.
  class Principal
    # type: :email | :username | :phone
    attr_reader :type

    def initialize(type:, required: true, login: false, permanent: false)
      @type = type.to_sym
      @required = required
      @login = login
      @permanent = permanent
    end

    def required? = @required
    def optional? = !@required
    # a key the sign-in form accepts
    def login?    = @login

    # Fixed once the account holds it: no self-serve change surface is generated
    # for it. The column stays writable, so an admin or a console still can.
    def permanent? = @permanent
    def changeable? = !@permanent

    # A channel can receive a message (verification, reset, magic link, OTP).
    def channel?  = type != :username

    # "email" / "username" / "phone"
    def column    = type.to_s
    # Form label text. Every principal type is a single word, so a plain
    # capitalize matches humanize without pulling ActiveSupport into the gem's
    # otherwise dependency-free load path (the host Rails app provides it at
    # generation time, but the value object is unit-tested standalone).
    def label     = type.to_s.capitalize

    # Form helper + autocomplete token for generated views.
    def field_helper
      { email: "email_field", phone: "telephone_field", username: "text_field" }.fetch(type)
    end

    def autocomplete
      { email: "email", phone: "tel", username: "username" }.fetch(type)
    end

    # Model-layer expressions, emitted verbatim into user.rb.tt. Keeping them
    # here (not scattered in the template) keeps the template readable and the
    # per-type differences in one place.
    def validation
      case type
      # disposable_domain, not disposable: the plain option also resolves the
      # domain's MX servers, putting a DNS lookup inside a validation. This one
      # is a lookup against the gem's bundled list, in-process and offline.
      when :email    then '"valid_email_2/email": { disposable_domain: true }'
      when :phone    then %() # validated by an inline Phonelib validate block
      # Letters (both cases), digits, underscore; 3–20 chars; at least one letter;
      # no "@". The ≥1-letter rule is what makes the sign-in dispatch a total,
      # unambiguous partition: "@" → email, else a letter → username, else
      # → phone — a username always has a letter, a phone never does. Relaxing it
      # to allow all-digit names reopens the username/phone ambiguity. Case is
      # preserved for display; uniqueness folds case via the functional index below.
      when :username then %q(format: { with: /\A(?=.*[a-zA-Z])[a-zA-Z0-9_]{3,20}\z/ })
      end
    end

    # Everything after `validates :<column>, ` on the model's validation line.
    # A required principal gets `presence: true, <validation>`; an optional one
    # drops presence and allows nil, so a blank submission (normalized to nil
    # below) skips validation and rides the partial unique index.
    def validates_arguments
      rule = validation.to_s.strip
      [
        ("presence: true" if required?),
        (rule unless rule.empty?),
        ("allow_nil: true" if optional?)
      ].compact.join(", ")
    end

    # Phone can't ride the generic `validates :col, <format>` line: its validity
    # is a Phonelib.valid? check (a custom validator, not a `format:` matcher), and
    # when guests exist it must skip them (guests carry a nil phone). The template
    # emits its own lines instead.
    def dedicated_validation? = type == :phone

    # Sign-in dispatch: when one form field accepts several login keys, the
    # lookup is routed to a column by a *structural* test of the submitted string —
    # an email has "@", a username has a letter (guaranteed by the format), a phone
    # has neither. #login_dispatch_test is that test; the lowest-priority present
    # key needs none (it's the fallback). Email must be tested before username
    # because an email address also contains letters.
    def login_dispatch_test
      case type
      when :email    then %(identifier.include?("@"))
      when :username then %(identifier.match?(/[a-zA-Z]/))
      when :phone    then nil
      end
    end

    # The no-password lookup for this key, as a Ruby expression over a stripped
    # `identifier` local — used by the model's find_by_login. Email and phone pass
    # the raw identifier and lean on `normalizes` being applied inside finders
    # (downcase / E.164); username needs an explicit LOWER() match because its
    # normalization is strip-only (case is folded for uniqueness, not on write).
    def find_by_login_lookup
      case type
      when :email    then %(find_by(email: identifier))
      when :username then 'find_by("LOWER(username) = ?", identifier.downcase)'
      when :phone    then %(find_by(phone: identifier))
      end
    end

    # The same lookup, but verifying a password — used by the model's
    # authenticate_with_password. Channel keys go through authenticate_by, which
    # equalizes timing whether or not a row was found. It only hashes a decoy on a
    # miss, though, so a found row without a password would skip the hash entirely:
    # with_password makes that row a miss too. Username can't, because its lookup
    # needs LOWER() to fold case, so that arm finds first and authenticates second.
    # The asymmetry is safe: a username is a public identifier, so it is honest
    # about existence anyway.
    def authenticate_lookup
      case type
      when :email then %(with_password.authenticate_by(email: identifier, password:))
      when :username
        'find_by("LOWER(username) = ?", identifier.downcase)&.then { |user| user if user.authenticate(password) }'
      when :phone then %(with_password.authenticate_by(phone: identifier, password:))
      end
    end

    # +config_reference+ is the generated app's config constant ("UserAuth"), which
    # the phone branch reads a default country from. It's threaded in rather than
    # derived here because it belongs to the identity, not to the principal — see
    # Identity#config_reference, the same value the initializer template writes.
    def normalization(config_reference:)
      base =
        case type
        when :email    then "it.strip.downcase"
        # Strip only — the chosen case is stored and displayed verbatim.
        when :username then "it.strip"
        # A number typed without a leading "+" is read as though dialled inside
        # config.phone.default_country. Passing that country to parse as an
        # ARGUMENT is what suppresses Phonelib's fallback of reading a bare
        # number's leading digits AS a country code — which would turn a mistyped
        # local number into a valid foreign one ("6494461709" comes back a good NZ
        # number). Setting Phonelib.default_country globally does NOT do this.
        #
        # #to_s returns E.164 when the number parses and the original string
        # otherwise, so an uninterpretable number reaches the validator looking the
        # way the user typed it, and is rejected there.
        when :phone    then "Phonelib.parse(it, #{config_reference}.phone.default_country).to_s"
        end
      # An optional principal must collapse a blank submission to nil so the
      # partial unique index (WHERE <col> IS NOT NULL) and allow_nil both apply.
      # Required principals normalize without it.
      base += ".presence" if optional?
      "-> { #{base} }"
    end

    # Whether flows may reveal that a value is taken. Usernames are public
    # identifiers: sign-up MUST honestly reject a taken username. Channel
    # principals stay coy.
    def publicly_unique? = type == :username

    # The `t.string` line for create_users_migration. Principals whose uniqueness
    # can't ride an inline `index:` option (username — see
    # #functional_unique_index?) emit a bare column here and their index
    # separately.
    #
    # +nullable+ defaults to requiredness but is overridden for a *required* phone
    # in a --guestable build, where guests carry a nil number so the constraint has
    # to live in the model (unless: :guest?) rather than in NOT NULL.
    def migration_field(nullable: optional?)
      case type
      when :username then "t.string :username, null: false"
      when :email
        # Optional email drops NOT NULL and rides a partial unique index, so
        # multiple rows may hold NULL while set values stay unique.
        if required?
          "t.string :email,           null: false, index: { unique: true }"
        else
          %(t.string :email, index: { unique: true, where: "email IS NOT NULL" })
        end
      else
        null_option = " null: false," unless nullable
        where = %(, where: "#{column} IS NOT NULL") if nullable
        "t.string :#{column},#{null_option} index: { unique: true#{where} }"
      end
    end

    # Username uniqueness is case-insensitive but its stored value keeps its
    # display case, so it can't use migration_field's inline unique index. It
    # rides a functional unique index on LOWER(column) instead, emitted
    # separately. SQLite and PostgreSQL take it as written; MySQL wants the
    # expression in a second pair of parens.
    def functional_unique_index? = type == :username
  end
end
