# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  class EmailValidationTest < GeneratorTestCase
    def test_email_builds_use_valid_email2_everywhere_an_address_is_entered
      run_generator %w[--password --registration=open-and-invites --email --phone=optional]

      assert_file "Gemfile", /gem "valid_email2"/
      assert_file "app/models/concerns/principals.rb",
                  %r{validates :email, presence: true, "valid_email_2/email": \{ disposable_domain: true \}}
      assert_file "app/models/user/email_verifiable.rb",
                  %r{validates :pending_email, "valid_email_2/email": \{ disposable_domain: true \}, allow_nil: true}
      assert_file "app/models/invitation.rb",
                  %r{validates :sent_to, "valid_email_2/email": \{ disposable_domain: true \}, if: :email_addressed\?}
      assert_file "test/models/user_test.rb", /malformed emails are rejected/
    end

    def test_optional_email_keeps_blank_values_optional
      run_generator %w[--password --username --email=optional --no-contactable]

      assert_file "app/models/concerns/principals.rb",
                  %r{validates :email, "valid_email_2/email": \{ disposable_domain: true \}, allow_nil: true}
    end

    # Every address a build accepts goes through the same rule, or rejecting a
    # throwaway domain at sign-up is undone by changing to one afterwards.
    def test_disposable_domains_are_refused_wherever_an_address_is_entered
      run_generator %w[--password --registration=open-and-invites --email]

      %w[
        app/models/concerns/principals.rb
        app/models/user/email_verifiable.rb
        app/models/invitation.rb
      ].each { |model| assert_file model, /disposable_domain: true/ }
    end

    def test_email_less_builds_do_not_depend_on_valid_email2
      run_generator %w[--password --phone=required]

      assert_file "Gemfile" do |gemfile|
        assert_no_match(/gem "valid_email2"/, gemfile)
      end
    end
  end
end
