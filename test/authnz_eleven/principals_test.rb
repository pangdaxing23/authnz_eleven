# frozen_string_literal: true

require "test_helper"

# Unit coverage for the Principals collection built from explicit flags.
module AuthnzEleven
  # derived answer, and the length is just how many answers the collection gives.
  class PrincipalsTest < Minitest::Test
    def test_from_options_without_principal_flags_is_empty
      assert_empty AuthnzEleven::Principals.from_options({}).to_a
    end

    def test_from_options_reads_permanent_as_a_modifier_on_the_requiredness
      principals = AuthnzEleven::Principals.from_options(email: "required,permanent", phone: "optional,permanent")
      assert principals.email.required?
      assert principals.email.permanent?
      refute principals.email.changeable?
      assert principals.phone.optional?
      assert principals.phone.permanent?
    end

    def test_from_options_without_permanent_leaves_every_principal_changeable
      principals = AuthnzEleven::Principals.from_options(email: "required", phone: "required")
      assert principals.email.changeable?
      assert principals.phone.changeable?
    end

    def test_split_mode_separates_requiredness_from_modifiers
      assert_equal ["required", ["permanent"]], AuthnzEleven::Principals.split_mode(" Required , Permanent ")
      assert_equal ["optional", []], AuthnzEleven::Principals.split_mode("optional")
      assert_equal ["", []], AuthnzEleven::Principals.split_mode(nil)
    end

    def test_from_options_email_optional_builds_an_optional_login_email
      principals = AuthnzEleven::Principals.from_options(email: "optional")
      email = principals.email
      assert email.optional?
      assert email.login?
      assert_equal %i[email], principals.login_principals.map(&:type)
    end

    def test_from_options_reddit_model_is_required_username_plus_optional_email
      principals = AuthnzEleven::Principals.from_options(username: true, email: "optional")
      assert principals.username.required?
      assert principals.email.optional?
      # both are login keys; username is the display principal
      assert principals.multi_login?
      assert_equal :username, principals.display.type
    end

    def test_from_options_with_username_builds_one_login_key
      principals = AuthnzEleven::Principals.from_options(username: true)
      refute principals.multi_login?
      assert_equal %i[username], principals.login_principals.map(&:type)
      assert_equal :username, principals.display.type
    end

    def test_from_options_phone_required_is_the_only_login_key_without_email
      principals = AuthnzEleven::Principals.from_options(phone: "required")
      refute principals.multi_login?
      assert_equal %i[phone], principals.login_principals.map(&:type)
      assert_equal :phone, principals.display.type
      assert principals.phone.required?
    end

    def test_from_options_phone_optional_is_a_login_key_but_not_required
      principals = AuthnzEleven::Principals.from_options(phone: "optional")
      assert principals.phone.optional?
      assert principals.phone.login?
      assert_empty principals.required
    end

    def test_sms_code_does_not_imply_a_phone
      assert_nil AuthnzEleven::Principals.from_options(sms_code: true).phone
    end

    def test_from_options_phone_only_login_when_email_absent
      # --phone=required: phone is the sole login key, and display.
      principals = AuthnzEleven::Principals.from_options(phone: "required", username: nil)
      assert_equal %i[phone], principals.login_principals.map(&:type)
      assert_equal :phone, principals.display.type
    end

    def test_display_expression_collapses_to_one_column_for_a_single_login_key
      principals = AuthnzEleven::Principals.from_options(email: "required")
      assert_equal "user.email", principals.display_expression("user")
    end

    # The case #display alone cannot answer: --contactable promises a channel
    # without saying which, so a build-time pick is nil on every account that
    # happened to give the other one.
    def test_display_expression_reads_down_the_precedence_when_channels_are_optional
      principals = AuthnzEleven::Principals.from_options(email: "optional", phone: "optional")
      assert_equal :email, principals.display.type
      assert_equal "u.email || u.phone", principals.display_expression("u")
    end

    # A required username is NOT NULL, so it answers for every row and the channels
    # behind it are unreachable — no fallback even with two optional channels.
    def test_display_expression_stops_at_the_first_required_principal
      principals = AuthnzEleven::Principals.from_options(username: true, email: "optional", phone: "optional")
      assert_equal "u.username", principals.display_expression("u")
    end

    def test_display_expression_keeps_the_first_required_principal_after_an_optional_one
      principals = AuthnzEleven::Principals.from_options(email: "optional", phone: "required")
      assert_equal "u.email || u.phone", principals.display_expression("u")
    end

    def test_type_finders
      principals = build(email: [true, true], username: [true, true])
      assert_equal :email, principals.email.type
      assert_equal :username, principals.username.type
      assert_nil principals.phone
    end

    def test_login_channels_and_required_selectors
      principals = build(username: [true, true], email: [false, false], phone: [true, false])
      assert_equal %i[username], principals.login_principals.map(&:type)
      assert_equal %i[email phone], principals.channels.map(&:type)
      assert_equal %i[username phone], principals.required.map(&:type)
    end

    def test_display_prefers_username_then_email_then_phone
      assert_equal :email, build(email: [true, true]).display.type
      assert_equal :username, build(email: [true, true], username: [true, true]).display.type
      assert_equal :phone, build(phone: [true, true]).display.type
    end

    def test_multi_login
      refute build(email: [true, true]).multi_login?
      assert build(email: [true, true], username: [true, true]).multi_login?
    end

    private

    # build(email: [required, login], username: [...], ...) — small helper so each
    # test spells out only the principals it cares about.
    def build(**spec)
      list = spec.map do |type, (required, login)|
        AuthnzEleven::Principal.new(type: type, required: required, login: login)
      end
      AuthnzEleven::Principals.new(list)
    end
  end
end
