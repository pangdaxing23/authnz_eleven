# frozen_string_literal: true

require "test_helper"
require "authnz_eleven/wizard"

module AuthnzEleven
  # The wizard's two halves, tested without a terminal: what each screen offers
  # given the answers above it, and what the answers emit as a command line.
  #
  # That the emitted flags are ones the generator accepts is a separate tier —
  # test/generators/wizard_flags_test.rb walks the whole matrix.
  class WizardTest < Minitest::Test
    def setup
      @wizard = Wizard.new
      answers.doors = ["password"]
    end

    def answers = @wizard.answers
    def flags = @wizard.to_flags
    def offers(screen) = @wizard.send(screen).map(&:last)

    # ---- emitting ------------------------------------------------------

    # Principals are explicit. Registration, verification, coyness and
    # contactability use their generator defaults and stay silent.
    def test_a_default_build_emits_the_principal_and_door
      assert_equal ["--email=required", "--password"], flags
    end

    def test_defaults_turned_off_emit_their_negative
      answers.contactable = false
      answers.verify = false

      expected = ["--email=required", "--password", "--no-verifiable", "--no-contactable"]
      assert_equal expected.sort, flags.sort
    end

    def test_coyness_is_opt_in
      answers.coy = true

      assert_includes flags, "--coy"
    end

    def test_a_required_password_emits_the_bare_flag
      answers.password_mode = "required"

      assert_includes flags, "--password"
    end

    def test_a_non_default_password_mode_names_its_value
      answers.doors = %w[password passkey]
      answers.password_mode = "optional"

      assert_includes flags, "--password=optional"
    end

    def test_permanence_rides_the_principal_flag
      answers.permanent = %w[email phone]
      answers.phone = "required"

      assert_includes flags, "--email=required,permanent"
      assert_includes flags, "--phone=required,permanent"
    end

    def test_api_tokens_are_independent_of_sessions
      answers.api_tokens = true

      assert_includes flags, "--api-tokens"
      assert_empty answers.sessions
    end

    def test_teams_is_one_flag_or_the_other_never_both
      answers.teams = "scope"

      assert_includes flags, "--teams"
      refute_includes flags, "--teams=session"
    end

    # --admin-dashboard already turns --adminable on, so naming both is noise.
    def test_an_implied_flag_is_not_also_named
      answers.admin = %w[adminable admin_dashboard]

      assert_includes flags, "--admin-dashboard"
      refute_includes flags, "--adminable"
    end

    def test_invitation_only_registration_is_a_single_flag
      answers.registration = "invite-only"

      assert_includes flags, "--registration=invite-only"
      refute_includes flags, "--registration=open-and-invites"
    end

    def test_password_rules_are_dropped_with_the_password_door
      answers.doors = ["passkey"]
      answers.password_extras = %w[pwned recoverable]

      refute_includes flags, "--pwned"
      refute_includes flags, "--recoverable"
    end

    def test_second_factors_join_into_one_flag
      answers.second_factor = %w[totp webauthn]

      assert_includes flags, "--second-factor=totp,webauthn"
    end

    # ---- what each screen offers ---------------------------------------

    def test_a_door_is_only_offered_a_channel_it_can_reach
      answers.email = "none"
      answers.phone = "none"
      answers.username = true

      refute_includes offers(:door_options), "magic_link"
      refute_includes offers(:door_options), "sms_code"
    end

    def test_sms_is_offered_once_there_is_a_phone
      answers.phone = "required"

      assert_includes offers(:door_options), "sms_code"
    end

    def test_a_texted_second_factor_needs_a_phone_and_no_texted_door
      refute_includes offers(:second_factor_options), "sms"

      answers.phone = "required"
      assert_includes offers(:second_factor_options), "sms"

      answers.doors = %w[sms_code]
      refute_includes offers(:second_factor_options), "sms"
    end

    def test_sudo_needs_something_to_ask_for
      assert_includes offers(:protection_options), "sudoable"

      answers.doors = %w[magic_link]

      refute_includes offers(:protection_options), "sudoable"

      answers.second_factor = %w[totp]

      assert_includes offers(:protection_options), "sudoable"
    end

    # A list built from earlier answers must be a block: the whole form is
    # constructed before the first screen is shown.
    def test_every_answer_dependent_option_list_is_built_lazily
      source = File.read(File.expand_path("../../lib/authnz_eleven/wizard.rb", __dir__))

      assert_empty source.scan(/\.options\(\*menu\((\w+)\)\)/).flatten.grep_v(/\A[A-Z_]+\z/)
    end

    def test_an_optional_password_needs_another_door_to_be_optional_against
      refute_includes offers(:password_mode_options), "optional"

      answers.doors = %w[password omniauth]

      assert_includes offers(:password_mode_options), "optional"
    end

    def test_a_deferred_password_needs_something_to_defer_past
      assert_includes offers(:password_mode_options), "deferred"

      answers.verify = false

      refute_includes offers(:password_mode_options), "deferred"

      answers.doors = %w[password passkey]

      assert_includes offers(:password_mode_options), "deferred"
    end

    def test_invitations_need_a_channel_to_be_sent_to
      answers.email = "none"
      answers.username = true

      refute_includes offers(:registration_options), "invite_only"
      assert_includes offers(:registration_options), "open"
    end

    # Every sign-up path proves a required phone before the account exists, so the
    # number is there from the start and permanence is always on offer.
    def test_a_required_phone_can_always_be_permanent
      answers.phone = "required"

      %w[closed open].each do |registration|
        answers.registration = registration
        assert_includes offers(:permanent_options), "phone"
      end
    end

    def test_an_optional_channel_is_never_offered_as_permanent
      answers.email = "optional"
      answers.phone = "optional"

      assert_empty offers(:permanent_options)
    end
  end
end
