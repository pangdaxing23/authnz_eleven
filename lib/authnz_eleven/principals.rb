# frozen_string_literal: true

require_relative "principal"

module AuthnzEleven
  # The ordered set of principals for one generator run. Where Identity names
  # things (class, table, routes), Principals shapes the account's identifying
  # columns and the flows that ride on them.
  #
  # Email and phone are opt-in principals; a bare flag makes the selected
  # principal required. Every valid build has at least one principal.
  class Principals
    include Enumerable

    REQUIREDNESS = %w[required optional].freeze

    # Build the set from the generator's parsed options. --username prepends a
    # required login principal, and --email / --phone add channel principals.
    def self.from_options(options)
      # Ordered username, email, phone so #display prefers them in that order and
      # the sign-in dispatch tests the most specific keys first. Each channel
      # helper returns nil when its flag omits it.
      list = [
        (Principal.new(type: :username, required: true, login: true) if options[:username]),
        email_principal(options[:email]),
        phone_principal(options[:phone])
      ].compact
      new(list)
    end

    # A --email / --phone value is a requiredness word, optionally followed by the
    # word "permanent" — the only modifier a principal takes:
    # "required,permanent" -> [ "required", [ "permanent" ] ]. The generator
    # validates the words; this only splits them.
    def self.split_mode(value)
      requiredness, *modifiers = value.to_s.split(",").map { it.strip.downcase }.reject(&:empty?)
      [requiredness.to_s, modifiers]
    end

    def self.permanent?(modifiers) = modifiers == %w[permanent]

    # The email principal for the given --email mode, or nil when email is off.
    def self.email_principal(mode)
      requiredness, modifiers = split_mode(mode)
      return unless %w[required optional].include?(requiredness)

      Principal.new(type: :email, required: requiredness == "required", login: true,
                    permanent: permanent?(modifiers))
    end

    # The phone principal for the given --phone mode, or nil when phone is off.
    # Phone is a login key too (the sign-in form dispatches to it).
    def self.phone_principal(mode)
      requiredness, modifiers = split_mode(mode)
      return unless %w[required optional].include?(requiredness)

      Principal.new(type: :phone, required: requiredness == "required", login: true,
                    permanent: permanent?(modifiers))
    end

    def initialize(list)
      @list = list
    end

    def each(&) = @list.each(&)

    def email    = find { |p| p.type == :email }
    def username = find { |p| p.type == :username }
    def phone    = find { |p| p.type == :phone }

    def login_principals = select(&:login?)

    # Login keys in *dispatch* priority for the sign-in form's shape test:
    # email first (its "@" is the most specific test), then username (a letter),
    # then phone (the fallback). Distinct from #login_principals' list order, which
    # follows display preference (username first).
    def login_dispatch_principals
      login_principals.sort_by { |p| %i[email username phone].index(p.type) }
    end

    def channels         = select(&:channel?)
    def required         = select(&:required?)

    # The principal shown in UI/admin/WebAuthn: the first login principal
    # (username when present, else email, else phone).
    def display
      login_principals.min_by { |p| %i[username email phone].index(p.type) }
    end

    # #display names one column for the whole build, which is what a table header
    # or a WebAuthn handle wants. Showing a person their own identifier is a
    # record-level question instead: --contactable's Reddit shape
    # (--email=optional --phone=optional) promises each account holds *a* channel
    # without saying which, so the build-time pick is nil on half the rows.
    #
    # Only an OPTIONAL principal can be nil at the front of that precedence, so the
    # fallback stops at the first required one: a required username or email is
    # NOT NULL (guests get a synthesized one), which makes everything after it
    # unreachable. A required phone is the exception — nullable under --guestable
    # and while verification is outstanding — but phone sorts last and so never
    # leads. Most builds therefore emit a bare column read.
    def display_expression(receiver)
      ordered = login_principals.sort_by { |p| %i[username email phone].index(p.type) }
      reachable = ordered.take_while(&:optional?) + ordered.drop_while(&:optional?).take(1)
      reachable.map { |p| "#{receiver}.#{p.column}" }.join(" || ")
    end

    # Whether the sign-in form must dispatch between several login keys.
    def multi_login? = login_principals.size > 1
  end
end
