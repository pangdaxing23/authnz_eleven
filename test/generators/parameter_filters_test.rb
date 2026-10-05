# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # The parameter filters appended to config/initializers/filter_parameter_logging.rb.
  # Rails' stock list is written against a stock app; these tests pin which of this
  # build's own columns and params get added to it, that the host's file is only
  # ever appended to, and that nothing is added twice (a re-run, or a second
  # identity that shares a filter with the first).
  class ParameterFiltersTest < GeneratorTestCase
    INITIALIZER = "config/initializers/filter_parameter_logging.rb"
    STOCK_LINE = /:passw, :email, :secret, :token/

    def test_omniauth_filters_uid_and_the_callback_code
      run_generator %w[--password --registration=open --omniauth --email]

      assert_file INITIALIZER do |contents|
        # The host's own list is left where it was ...
        assert_match STOCK_LINE, contents
        # ... and ours is appended below it.
        assert_match(/filter_parameters \+= \[ .*#{Regexp.escape('/\Auid\z/')}/, contents)
        assert_match('/\Acode\z/', contents)
      end
    end

    def test_phone_build_filters_the_number_but_not_its_timestamp
      run_generator %w[--password --registration=open --phone=required]

      assert_file INITIALIZER do |contents|
        assert_match('/\Aphone\z/', contents)
        # Anchored, so phone_verified_at stays readable in a log.
        refute_match(/:phone\b/, contents)
        # The unproved number, which /\Aphone\z/ does not reach.
        assert_match('/\Apending_phone\z/', contents)
      end
    end

    def test_a_build_that_mails_a_link_filters_the_bearer_token
      run_generator %w[--password --registration=open --recoverable --email]

      assert_file INITIALIZER do |contents|
        assert_match('/\Asid\z/', contents)
      end
    end

    def test_a_multi_key_build_filters_the_login_pair
      run_generator %w[--password --registration=open --username --email]

      assert_file INITIALIZER do |contents|
        assert_match('/\Alogin\z/', contents)
        assert_match('/\Alogin_hint\z/', contents)
        refute_match(/Ausername_hint/, contents)
      end
    end

    # takes --username OR --phone=required, so phone can be the sole key.
    def test_a_phone_only_login_build_filters_its_hint
      run_generator %w[--password --phone=required]

      assert_file INITIALIZER do |contents|
        assert_match('/\Aphone_hint\z/', contents)
        refute_match(/Alogin\\z/, contents)
      end
    end

    def test_invitation_build_filters_its_recipient
      run_generator %w[--password --registration=open-and-invites --email]

      assert_file INITIALIZER do |contents|
        assert_match('/\Asent_to\z/', contents)
        refute_match(/Auid/, contents) # no --omniauth
        refute_match(/Aphone/, contents) # no --phone
        refute_match(/Acode/, contents)  # nothing in this build takes a code
      end
    end

    def test_a_build_with_nothing_to_add_leaves_the_file_alone
      before = File.read(File.join(destination_root, INITIALIZER))

      # No email channel, no phone, no codes: nothing here the stock list misses.
      run_generator %w[--password --registration=open --username]

      assert_equal before, File.read(File.join(destination_root, INITIALIZER))
    end

    def test_filters_already_present_are_not_appended_again
      path = File.join(destination_root, INITIALIZER)
      File.write(path, "#{File.read(path)}\nRails.application.config.filter_parameters += [ /\\Auid\\z/ ]\n")

      run_generator %w[--password --registration=open --omniauth --email]

      contents = File.read(path)
      assert_equal 1, contents.scan('/\Auid\z/').length
      # The callback code is still added beside the existing provider id.
      assert_match('/\Acode\z/', contents)
    end

    def test_a_missing_initializer_is_reported_instead_of_created
      FileUtils.rm File.join(destination_root, INITIALIZER)

      output = run_generator %w[--password --registration=open --omniauth --email]

      refute File.exist?(File.join(destination_root, INITIALIZER)),
             "the host app's filter initializer should not be created for it"
      assert_match(/filter_parameters \+= \[ .*Auid/, output)
    end
  end
end
