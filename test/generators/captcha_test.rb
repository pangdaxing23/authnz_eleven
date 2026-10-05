# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # The captcha strategy's key sourcing. A missing key used to render an empty
  # sitekey, which rejects every submission with a message blaming the user —
  # silent in development and, worse, silent in production. These pin the two
  # halves of the fix: development works with no keys at all, and anywhere else
  # a missing key says so.
  class CaptchaTest < GeneratorTestCase
    STRATEGY = "app/lib/captcha/turnstile.rb"

    def test_development_falls_back_to_cloudflares_published_test_keys
      run_generator %w[--password --registration=open --captchable --email]

      assert_file STRATEGY do |contents|
        assert_match "1x00000000000000000000AA", contents
        assert_match "1x0000000000000000000000000000000AA", contents
        assert_match(/unless Rails\.env\.local\?/, contents)
      end
    end

    def test_a_missing_key_raises_outside_development
      run_generator %w[--password --registration=open --captchable --email]

      assert_file STRATEGY, /raise "Set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY/
    end

    # The widget does not survive a Turbo body swap, and these forms re-render on failure.
    def test_captchad_forms_opt_out_of_turbo
      run_generator %w[--password --registration=open --recoverable --magic-link
                       --sms-code --captchable --email --phone]

      captcha_forms.each { |form| assert_file form, /form_with url: .*data: \{turbo: false\}/ }
    end

    def test_forms_keep_turbo_without_a_captcha
      run_generator %w[--password --registration=open --recoverable --magic-link --sms-code --email --phone]

      captcha_forms.each { |form| assert_file(form) { |contents| refute_match "turbo: false", contents } }
    end

    # Before the lookup, so a rejected challenge neither leaks whether the account
    # exists nor spends one of its deadbolt attempts.
    def test_sign_in_verifies_the_captcha_before_authenticating
      run_generator %w[--password --registration=open --deadboltable --captchable --email]

      assert_file "app/controllers/users/sessions_controller.rb" do |contents|
        assert_operator contents.index("captcha_verified?"), :<, contents.index("authenticate_with_password")
      end
    end

    private

    def captcha_forms
      %w[
        app/views/users/sessions/new.html.erb
        app/views/users/registrations/new.html.erb
        app/views/users/password_resets/new.html.erb
        app/views/users/magic_link/new.html.erb
        app/views/users/sms_sessions/new.html.erb
      ]
    end
  end
end
