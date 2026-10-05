# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # An invite-only build that signs in with a provider admits on the address the
  # provider reported. That question is asked at the callback, which then stages a
  # row holding the invitation; the invitation is accepted when the row becomes an
  # account.
  class InviteOnlyOmniauthTest < GeneratorTestCase
    CALLBACK = "app/controllers/users/omniauth_controller.rb"

    def test_the_callback_admits_on_the_provider_address
      run_generator %w[--omniauth --username --email --registration=invite-only]

      assert_file CALLBACK do |contents|
        assert_match "unless pending_invitation_for(omniauth.info.email)", contents
        assert_match "registration.invitation = pending_invitation_for(omniauth.info.email)", contents
      end
    end

    def test_the_invitation_is_accepted_when_the_account_is_created
      run_generator %w[--omniauth --username --email --registration=invite-only]

      assert_file "app/models/pending_registration.rb", /invitation&\.accept\(user\)/
    end

    def test_an_invitable_open_build_attaches_the_invitation_without_gating
      run_generator %w[--omniauth --username --email --registration=open-and-invites]

      assert_file CALLBACK do |contents|
        refute_match "unless pending_invitation_for", contents
        assert_match "registration.invitation = pending_invitation_for(omniauth.info.email)", contents
      end
    end

    def test_an_open_build_carries_neither_check
      run_generator %w[--omniauth --username --email --registration=open]

      assert_file CALLBACK do |contents|
        refute_match "pending_invitation_for", contents
      end
    end
  end
end
