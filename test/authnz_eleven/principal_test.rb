# frozen_string_literal: true

require "test_helper"

# Unit coverage for the Principal value object. It derives a per-type expression
# for each of email, username and phone, so every branch is exercised here even
# where a given build would never reach it.
module AuthnzEleven
  class PrincipalTest < Minitest::Test
    def email    = AuthnzEleven::Principal.new(type: :email, required: true, login: true)
    def username = AuthnzEleven::Principal.new(type: :username, required: true, login: true)
    def phone    = AuthnzEleven::Principal.new(type: :phone, required: false)

    def test_type_is_symbolized
      assert_equal :email, AuthnzEleven::Principal.new(type: "email").type
    end

    def test_required_and_optional_are_inverses
      assert email.required?
      refute email.optional?
      refute phone.required?
      assert phone.optional?
    end

    def test_login_flag
      assert email.login?
      refute phone.login?
    end

    def test_only_username_is_not_a_channel
      assert email.channel?
      assert phone.channel?
      refute username.channel?
    end

    def test_column_and_label
      assert_equal "email", email.column
      assert_equal "Email", email.label
      assert_equal "Username", username.label
    end

    def test_field_helper_per_type
      assert_equal "email_field", email.field_helper
      assert_equal "telephone_field", phone.field_helper
      assert_equal "text_field", username.field_helper
    end

    def test_autocomplete_per_type
      assert_equal "email", email.autocomplete
      assert_equal "tel", phone.autocomplete
      assert_equal "username", username.autocomplete
    end

    def test_validation_per_type
      assert_equal '"valid_email_2/email": { disposable_domain: true }', email.validation
      # Both cases allowed (case preserved for display), no "@".
      assert_equal "format: { with: /\\A(?=.*[a-zA-Z])[a-zA-Z0-9_]{3,20}\\z/ }", username.validation
    end

    def test_normalization_per_type
      assert_equal "-> { it.strip.downcase }", email.normalization(config_reference: "UserAuth")
      # Strip only — the chosen case is stored/displayed verbatim.
      assert_equal "-> { it.strip }", username.normalization(config_reference: "UserAuth")
      # The country is passed to parse as an ARGUMENT, which is what stops Phonelib
      # reading a bare number's leading digits as a country code. Optional here, so
      # it also collapses blank to nil (see below).
      assert_equal "-> { Phonelib.parse(it, UserAuth.phone.default_country).to_s.presence }",
                   phone.normalization(config_reference: "UserAuth")
    end

    # config_reference is the identity's, so a namespaced identity reads its own config.
    def test_normalization_uses_the_identitys_config_constant
      assert_equal "-> { Phonelib.parse(it, RealtorAuth.phone.default_country).to_s.presence }",
                   phone.normalization(config_reference: "RealtorAuth")
    end

    def test_optional_normalization_collapses_blank_to_nil
      # An optional principal must normalize a blank submission to nil so the
      # partial unique index and allow_nil both apply.
      optional_email = AuthnzEleven::Principal.new(type: :email, required: false, login: true)
      assert_equal "-> { it.strip.downcase.presence }",
                   optional_email.normalization(config_reference: "UserAuth")
    end

    def test_validates_arguments_per_requiredness
      assert_equal 'presence: true, "valid_email_2/email": { disposable_domain: true }', email.validates_arguments

      # Optional email drops presence and allows nil so blank rides the index.
      optional_email = AuthnzEleven::Principal.new(type: :email, required: false, login: true)
      assert_equal '"valid_email_2/email": { disposable_domain: true }, allow_nil: true',
                   optional_email.validates_arguments
    end

    def test_optional_email_migration_field_uses_partial_unique_index
      optional_email = AuthnzEleven::Principal.new(type: :email, required: false, login: true)
      assert_equal %(t.string :email, index: { unique: true, where: "email IS NOT NULL" }),
                   optional_email.migration_field
    end

    def test_only_username_is_publicly_unique
      assert username.publicly_unique?
      refute email.publicly_unique?
      refute phone.publicly_unique?
    end

    def test_email_migration_field_is_byte_for_byte_todays_line
      assert_equal "t.string :email,           null: false, index: { unique: true }",
                   email.migration_field
    end

    def test_username_migration_field_is_a_bare_column
      # Username can't ride an inline unique index (it folds case via a separate
      # functional index), so its column line carries no `index:` option.
      assert_equal "t.string :username, null: false", username.migration_field
    end

    def required_phone = AuthnzEleven::Principal.new(type: :phone, required: true, login: true)

    def test_phone_migration_field_without_verification_is_unchanged
      assert_equal "t.string :phone, null: false, index: { unique: true }",
                   required_phone.migration_field
      assert_equal %(t.string :phone, index: { unique: true, where: "phone IS NOT NULL" }),
                   phone.migration_field
    end

    def test_nullable_override_drops_not_null_for_a_required_principal
      # --guestable: guests carry a nil number, so a required phone's constraint
      # moves to the model validation and the column stays nullable.
      assert_equal %(t.string :phone, index: { unique: true, where: "phone IS NOT NULL" }),
                   required_phone.migration_field(nullable: true)
    end

    def test_find_by_login_lookup_per_type
      assert_equal "find_by(phone: identifier)", required_phone.find_by_login_lookup
      assert_equal "find_by(email: identifier)", email.find_by_login_lookup
      assert_equal %(find_by("LOWER(username) = ?", identifier.downcase)), username.find_by_login_lookup
    end

    # authenticate_by hashes a decoy only when no row is found, so a passwordless
    # row must be scoped out or it answers ~190 ms faster than a missing one.
    def test_channel_password_lookups_skip_passwordless_rows
      assert_equal "with_password.authenticate_by(email: identifier, password:)", email.authenticate_lookup
      assert_equal "with_password.authenticate_by(phone: identifier, password:)", required_phone.authenticate_lookup
    end

    def test_only_username_needs_a_functional_unique_index
      assert username.functional_unique_index?
      refute email.functional_unique_index?
      refute phone.functional_unique_index?
    end
  end
end
