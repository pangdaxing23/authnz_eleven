# frozen_string_literal: true

require_relative "generator_test_case"
require_relative "../../lib/authnz_eleven/wizard"

module AuthnzEleven
  # The wizard carries its own copy of the generator's constraint graph, in the
  # shape of which options each screen offers. This is what stops the two
  # drifting: walk every combination the wizard can reach and put its flags
  # through the generator's fail-fast validators. A validator that fires here is
  # a combination the wizard offered and the generator refuses.
  #
  # Only the axes the validators actually read are enumerated. The rest —
  # session behaviour, admin, teams — is bolted on as "everything at once" so a
  # new cross-flag rule about them still gets seen.
  class WizardFlagsTest < GeneratorTestCase
    EMAILS = %w[required optional none].freeze
    PHONES = %w[none required optional].freeze
    REGISTRATIONS = %w[closed open open-and-invites invite-only].freeze
    SECOND_FACTORS = [[], %w[totp webauthn]].freeze

    VALIDATORS = AuthnzElevenGenerator.public_instance_methods(false)
                                      .grep(/\A(validate|warn)_/).freeze

    # Both halves of the matrix can collapse to nothing and still pass: an empty
    # validator list checks nothing, and an over-tight reachability filter walks
    # nothing. Assert both are populated before trusting a green run.
    def test_the_matrix_is_not_vacuous
      assert_operator VALIDATORS.size, :>, 5, "no validators were found to run"
      assert_operator reachable.size, :>, 500, "the reachability filter walked almost nothing"
    end

    def test_every_reachable_combination_survives_the_generator
      refused = reachable.filter_map do |answers|
        flags = flags_for(answers)
        message = refusal_for(flags)
        "#{flags.join(" ")}\n    #{message}" if message
      end

      assert_empty refused, <<~MSG
        The wizard offered #{refused.size} combination(s) the generator refuses:

            #{refused.first(10).join("\n\n    ")}
      MSG
    end

    private

    # Drives the Answers object the way the screens would, honouring each
    # screen's own filtering, so only genuinely reachable states are produced.
    def reachable
      EMAILS.flat_map do |email|
        PHONES.flat_map do |phone|
          [true, false].flat_map do |username|
            [true, false].flat_map do |verify|
              combinations(email, phone, username, verify)
            end
          end
        end
      end
    end

    def combinations(email, phone, username, verify)
      base = Wizard::Answers.new
      base.email = email
      base.phone = phone
      base.username = username
      base.verify = verify
      return [] unless reachable_principals?(base)

      door_sets(base).product(SECOND_FACTORS).flat_map { |doors, second_factor| with_doors(base, doors, second_factor) }
    end

    # validate_identifier: something has to name the account at the sign-in form.
    def reachable_principals?(answers)
      answers.email? || answers.username || answers.phone.start_with?("required")
    end

    # Every non-empty subset of the doors this principal set offers, minus the
    # ones the doors screen's own validate would reject.
    def door_sets(answers)
      offered = %w[password passkey omniauth]
      offered << "magic_link" if answers.email?
      offered << "sms_code" if answers.phone?

      subsets(offered).reject do |doors|
        doors.empty? || (doors == ["sms_code"] && answers.phone == "optional")
      end
    end

    def subsets(items)
      (0..items.size).flat_map { |n| items.combination(n).to_a }
    end

    def with_doors(base, doors, second_factor)
      answers = dup_answers(base)
      answers.doors = doors
      answers.second_factor = second_factor
      answers.contactable = !answers.sole_optional_channel?

      password_modes(answers).product(registrations(answers)).map do |mode, registration|
        loaded = dup_answers(answers)
        loaded.password_mode = mode
        loaded.registration = registration
        load_everything_else(loaded)
      end
    end

    # The two invite answers need a channel to send an invitation to.
    def registrations(answers)
      answers.channels? ? REGISTRATIONS : %w[closed open]
    end

    def password_modes(answers)
      return ["required"] unless answers.password?

      modes = ["required"]
      modes << "optional" if answers.other_doors?
      modes << "deferred" if answers.password_deferrable?
      modes
    end

    # Turn on everything the screens would offer regardless of the axes above,
    # so a future rule coupling one of them to a principal or a door is caught.
    def load_everything_else(answers)
      answers.password_extras = password_extras(answers)
      answers.protections = ["captchable"]
      answers.protections << "sudoable" if answers.sudo_answerable?
      answers.protections << "security_notifications" if answers.email?
      answers.sessions = %w[rememberable timeoutable last_seenable trackable guestable easy_dev_login]
      answers.max_sessions = "evict"
      answers.api_tokens = true
      answers.teams = "scope"
      answers.admin = %w[adminable admin_dashboard impersonatable bannable]
      answers.encrypted = answers.channels?
      answers.coy = true
      answers.permanent = permanent_for(answers)
      answers
    end

    # Both, whenever the permanence screen would offer them — the maximal answer
    # is the one most likely to collide with something.
    def permanent_for(answers)
      [
        ("email" if answers.email == "required"),
        ("phone" if answers.phone_permanent?)
      ].compact
    end

    def password_extras(answers)
      return [] unless answers.password?

      extras = %w[pwned strong_passwords password_rotatable password_historical deadboltable]
      answers.email? ? extras + ["recoverable"] : extras
    end

    def dup_answers(answers)
      copy = Wizard::Answers.new
      answers.instance_variables.each { |v| copy.instance_variable_set(v, answers.instance_variable_get(v)) }
      copy
    end

    def flags_for(answers)
      wizard = Wizard.new
      answers.instance_variables.each { |v| wizard.answers.instance_variable_set(v, answers.instance_variable_get(v)) }
      wizard.to_flags
    end

    # Runs the fail-fast checks only: no files, no templates, just the
    # combination rules. warn_* methods say_status instead of raising, so they
    # are invoked too but can only fail by raising something unexpected.
    def refusal_for(flags)
      generator = AuthnzElevenGenerator.new([], flags, destination_root: destination_root)
      capture(:stdout) { VALIDATORS.each { |check| generator.send(check) } }
      nil
    rescue Rails::Generators::Error => e
      e.message.squish
    end
  end
end
